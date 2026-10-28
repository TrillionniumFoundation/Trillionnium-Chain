#!/usr/bin/env python3
"""Independently qualify finite pure-PoN pressure, not arbitrary-Sybil fairness.

Input validity and finite qualification are separate. Valid failure evidence is
retained and summarized; --require-qualified makes missing service, exhaustion
or actual overlap fail the gate. Local CPU observations are not hardware proofs.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct

SCHEMA = "pon-pure-pressure-v3"
PROFILE = "public-pure-pon-development-v2"
# The 0-bit, 2000ms policy vector is independently pinned by the native
# pure_admission_v2 signature-domain tests. A different digest needs a reviewed
# namespace/vector change, never an arbitrary well-shaped 32-byte declaration.
POLICY_ID = "f6854cd511f62e47b5d84dcb99b812e0f9df3f6ebe270f5d482933f1ea3bbc56"
PHASES = ("baseline", "from-zero", "correct-product-false-trace")
WINDOW = 30_000_000_000
BURST, RESERVE, REFILL = 2_000_000_000, 100_000_000, 250_000_000
ATTACKERS, CALL_CAP, ROUNDS = 24, 480, 3
PROOF_BYTES, PREFIX_BYTES = 4 + 3 * 4096 * 4 + 32, 4 + 3 * 4096 * 4
MAX_FILE_BYTES = 64 * 1024 * 1024
U64_MAX = (1 << 64) - 1
I128_MIN, I128_MAX = -(1 << 127), (1 << 127) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value):
    return type(value) is int and value >= 0


def wire_hash(tag, *parts):
    h = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag)
    for part in parts:
        h.update(struct.pack("<I", len(part)))
        h.update(part)
    return h.digest()


def raw_hex(value, size=None):
    require(type(value) is str and len(value) % 2 == 0, "hex value")
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("hex encoding") from error
    require(data.hex() == value and (size is None or len(data) == size), "canonical hex size")
    return data


def body_digest(request):
    # Request is a Rust internally tagged struct enum. Value/map serialization
    # in the report sorts keys; that order is NOT the original wire-body order.
    if request.get("op") == "submit":
        require(set(request) == {"op", "packet"}, "Submit wire fields")
        ordered = {"op": "submit", "packet": request["packet"]}
    elif request.get("op") == "history":
        require(set(request) == {"op", "tip", "after"}, "History wire fields")
        ordered = {"op": "history", "tip": request["tip"], "after": request["after"]}
    else:
        raise ValueError("unexpected request kind")
    raw = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()
    return wire_hash(b"public-request-body-v3", raw).hex()


def packet(raw):
    require(len(raw) >= 320 + PROOF_BYTES and raw[:6] == b"PNH1\x01\x00", "packet grammar")
    count = int.from_bytes(raw[318:320], "little")
    require(count <= 256, "packet transaction cap")
    pos, transactions = 320, []
    for _ in range(count):
        require(pos + 2 <= len(raw), "transaction length")
        size = int.from_bytes(raw[pos:pos + 2], "little")
        pos += 2
        require(159 <= size <= 2048 and pos + size <= len(raw), "transaction envelope bound")
        transactions.append(raw[pos:pos + size])
        pos += size
    proof = raw[pos:]
    require(len(proof) == PROOF_BYTES and proof[:4] == b"PNW1", "proof grammar")
    return {"raw": raw, "header": raw[:318], "transactions": transactions,
            "proof": proof, "id": wire_hash(b"block", raw[:318], proof[-32:]).hex(),
            "height": int.from_bytes(raw[102:110], "little"),
            "body": body_digest({"op": "submit", "packet": raw.hex()})}


def preparation(value):
    require(all(natural(value[k]) for k in ("seed_transfers", "seed_blocks", "business_blocks")),
            "integer fixture counts")
    require(value["schema"] == SCHEMA and value["seed_transfers"] == 1024
            and value["seed_blocks"] == 4 and value["business_blocks"] == 21, "business fixture")
    seed = [packet(raw_hex(p)) for p in value["seed"]]
    business = [packet(raw_hex(p)) for p in value["business"]]
    require(len(seed) == 4 and all(len(p["transactions"]) == 256 for p in seed), "seed coverage")
    require(len(business) == 21, "business block coverage")
    for index, item in enumerate(seed + business):
        require(item["height"] == index + 1, "chain height continuity")
        if index:
            require(item["header"][70:102].hex() == (seed + business)[index - 1]["id"], "parent chain")
    for index, item in enumerate(business):
        require(len(item["transactions"]) == (1 if index % 7 == 0 else 0), "signed business schedule")
    return business


def policy(value):
    require(all(natural(value[k]) for k in ("ticket_bits", "lifetime_ms", "call_deadline_ns")),
            "integer pure v2 policy")
    require(value["transport_profile"] == PROFILE and value["ticket_bits"] == 0
            and value["lifetime_ms"] == 2000 and value["call_deadline_ns"] == 2_000_000_000,
            "pure v2 policy, Hashcash or deadline change")
    require(value["policy_id"] == POLICY_ID, "signed v2 policy digest")


def no_authority(value):
    for key in ("public_fairness_qualified", "production_qualified", "work_hardness_qualified",
                "installation_authorized"):
        require(value[key] is False, "unearned authority or qualification")


def budget(value):
    require(all(natural(value[k]) for k in ("burst_ns", "start_reserve_ns", "refill_ns_per_second", "worker_limit")),
            "integer resource envelope")
    require(value["burst_ns"] == BURST and value["start_reserve_ns"] == RESERVE
            and value["refill_ns_per_second"] == REFILL and value["worker_limit"] == 2,
            "original CPU envelope changed")
    require(type(value["stored_credit_ns"]) is int and natural(value["in_flight"])
            and value["in_flight"] <= 2 and type(value["accounting_unavailable"]) is bool,
            "budget observation")


def flow(value, *, settled=False):
    if value is None:
        return False
    require(value["schema"] == "public-v3-local-actual-cpu-flow-v1", "flow schema")
    require(type(value["initial_credit_ns"]) is int and value["initial_credit_ns"] == 0
            and value["balance_identity_verified"] is True,
            "cold epoch or unavailable balance")
    for key in ("credited_refill_ns", "discarded_refill_ns", "booked_reservation_ns",
                "live_debited_cpu_ns", "settlement_residual_cpu_ns", "settled_full_cpu_ns",
                "unsettled_known_live_cpu_ns", "paid_cpu_debit_ns", "settlement_discard_ns", "live_owners"):
        require(natural(value[key]) and value[key] <= U64_MAX,
                "unknown, negative or overflowing actual CPU counter")
    require(value["live_owners"] <= 2
            and value["booked_reservation_ns"] == value["live_owners"] * RESERVE, "reservation identity")
    paid = value["live_debited_cpu_ns"] + value["settlement_residual_cpu_ns"]
    require(paid == value["paid_cpu_debit_ns"]
            == value["settled_full_cpu_ns"] + value["unsettled_known_live_cpu_ns"], "paid CPU double count")
    remaining = value["credited_refill_ns"] - paid - value["settlement_discard_ns"]
    require(type(value["remaining_paid_credit_ns"]) is int
            and type(value["stored_credit_ns"]) is int
            and I128_MIN <= value["remaining_paid_credit_ns"] <= I128_MAX
            and I128_MIN <= value["stored_credit_ns"] <= I128_MAX
            and remaining == value["remaining_paid_credit_ns"]
            and remaining - value["booked_reservation_ns"] == value["stored_credit_ns"], "actual credit conservation")
    if settled:
        require(value["live_owners"] == value["booked_reservation_ns"]
                == value["unsettled_known_live_cpu_ns"] == 0, "unjoined paid CPU")
    return True


def admission(value, expected_bytes):
    require(all(natural(value[k]) for k in ("fifo_capacity", "arithmetic_slots", "retained_software_bytes")),
            "integer admission resource envelope")
    require(value["schema"] == "public-pure-pon-admission-observation-v2"
            and value["fifo_capacity"] == 4 and value["arithmetic_slots"] == 64
            and value["retained_software_bytes"] == expected_bytes, "bounded pure v2 owner")
    for key in ("waiting", "registered", "started", "cancelled"):
        require(natural(value[key]), "admission counter")
    require(value["waiting"] <= 4
            and value["registered"] == value["waiting"] + value["started"] + value["cancelled"],
            "FIFO accounting")


def freshness_upper_bound(sample):
    value = sample["credit_freshness"]
    if value is None:
        return None
    require(type(value) is dict
            and value["schema"] == "public-v3-local-cpu-credit-freshness-v1", "freshness schema")
    f = value["actual_flow"]
    require(flow(f), "unknown freshness flow")
    for key in ("watermark_age_ns", "projected_credited_refill_ns", "projected_discarded_refill_ns"):
        require(natural(value[key]) and value[key] <= U64_MAX, "integer freshness refill counter")
    for key in ("projected_stored_credit_ns", "projected_paid_credit_ns"):
        require(type(value[key]) is int and I128_MIN <= value[key] <= I128_MAX,
                "signed freshness credit")
    require(type(value["projected_scalar_start_eligible"]) is bool, "freshness eligibility type")
    stored, booked = f["stored_credit_ns"], f["booked_reservation_ns"]
    ceiling = BURST - booked
    require(stored <= ceiling, "freshness reservation ceiling")
    # Age is the entire original watermark age, not a clamped sampling interval.
    # These projected refill fields are increments, not cumulative flow totals.
    offered = value["watermark_age_ns"] * REFILL // 1_000_000_000
    projected = min(stored + offered, ceiling)
    credited, discarded = projected - stored, stored + offered - projected
    require(value["projected_stored_credit_ns"] == projected
            and value["projected_credited_refill_ns"] == credited
            and value["projected_discarded_refill_ns"] == discarded
            and value["projected_paid_credit_ns"] == projected + booked,
            "freshness original refill projection")
    require(f["credited_refill_ns"] + credited <= U64_MAX
            and f["discarded_refill_ns"] + discarded <= U64_MAX, "freshness cumulative refill overflow")
    require(value["projected_scalar_start_eligible"] is
            (f["live_owners"] < 2 and projected >= RESERVE), "freshness scalar eligibility")
    require(all(natural(sample[k]) and sample[k] <= U64_MAX for k in ("started_ns", "ended_ns"))
            and sample["started_ns"] <= sample["ended_ns"], "freshness sample interval")
    # The read happened inside the entire interval. Allowing its full refill
    # duration gives an upper bound at sample end, even if the lock read was
    # early. Independent raw budget/flow reads may legitimately differ.
    elapsed = sample["ended_ns"] - sample["started_ns"]
    tail_refill = (elapsed * REFILL + 999_999_999) // 1_000_000_000
    return value["projected_paid_credit_ns"] + tail_refill


def depleted(sample):
    upper_bound = freshness_upper_bound(sample)
    f = sample["credit_freshness"]["actual_flow"] if upper_bound is not None else None
    return (f is not None and sample["clock_failures"] == 0
            and sample["budget"]["accounting_unavailable"] is False
            and upper_bound < RESERVE and f["paid_cpu_debit_ns"] > BURST - RESERVE)


def call(row):
    require(all(natural(row[k]) for k in ("started_ns", "ended_ns", "deadline_ns"))
            and row["started_ns"] < WINDOW and row["started_ns"] <= row["ended_ns"], "call clock")
    require(row["deadline_ns"] == min(WINDOW, row["started_ns"] + 2_000_000_000), "call deadline extended")
    require(natural(row["metrics"]["solution_trials"]) and row["metrics"]["solution_trials"] == 0,
            "Hashcash search reintroduced or noninteger trials")
    require(row["thread_cpu_ns"] is None or natural(row["thread_cpu_ns"]), "client CPU observation")
    require(row["status"] in ("ok", "refused", "error"), "call outcome")
    if row["response"] is not None:
        require(natural(row["response"]["solve_trials"]) and row["response"]["solve_trials"] == 0,
                "reply reports Hashcash or noninteger trials")
        require(row["response"]["ok"] is (row["status"] == "ok"), "response/status contradiction")
    raw_hex(row["body_digest"], 32)
    return row["status"] == "ok" and row["ended_ns"] <= row["deadline_ns"] and row["ended_ns"] < WINDOW


def attack_calls(report, business):
    calls, bodies, all_packets, healthy = [], {}, set(), True
    require(len(report["actors"]) == (0 if report["phase"] == "baseline" else ATTACKERS), "attacker population")
    actors_seen = set()
    for wrapper in report["actors"]:
        healthy &= wrapper["exit_success"] is True and wrapper["parent_forced_kill"] is False
        if wrapper["report"] is None or wrapper["report"]["error"] is not None:
            healthy = False
            continue
        actor = wrapper["report"]["result"]
        index = actor["actor"]
        require(type(index) is int and 0 <= index < ATTACKERS and index not in actors_seen, "actor identity")
        actors_seen.add(index)
        require(actor["policy"] == report["policy"] and actor["mode"] == report["phase"], "actor policy or mode")
        require(natural(actor["finished_ns"]), "actor completion clock")
        prefix = raw_hex(actor["acquisition"]["proof_prefix"], PREFIX_BYTES)
        require(prefix[:4] == b"PNW1", "actor proof prefix")
        require(prefix[4:4 + 2 * 4096 * 4] == business[0]["proof"][4:4 + 2 * 4096 * 4], "actor public task")
        if report["phase"] == "from-zero":
            require(prefix[4 + 2 * 4096 * 4:] == bytes(4096 * 4)
                    and actor["acquisition"]["correct_product_acquired_once"] is False, "from-zero shortcut concealed")
        else:
            require(prefix == business[0]["proof"][:-32]
                    and actor["acquisition"]["correct_product_acquired_once"] is True, "correct-product acquisition")
        require(actor["diagnostic_rejection"] in ("Transcript", "Product"), "false proof diagnostic")
        rows = actor["calls"]
        require(len(rows) <= CALL_CAP and actor["attempt_cap_reached"] is (len(rows) == CALL_CAP), "actor call cap")
        healthy &= bool(rows) and len(rows) < CALL_CAP and actor["finished_ns"] >= WINDOW
        for sequence, row in enumerate(rows):
            require(natural(row["sequence"]) and row["sequence"] == sequence, "omitted target trial group")
            call(row)
            require(row["status"] != "ok", "false transcript accepted")
            header = raw_hex(row["header"], 318)
            nonce = 10_000_000 + index * 1_000_000 + (0 if report["phase"] == "from-zero" else sequence)
            require(header == business[0]["header"][:310] + struct.pack("<Q", nonce), "challenge stream changed")
            challenge, trace = wire_hash(b"challenge", header), raw_hex(row["trace"], 32)
            trials = row["generation_trials"]
            require(type(trials) is int and 1 <= trials <= 4096, "target trial cap")
            for trial in range(trials):
                candidate = wire_hash(b"pure-pressure-false-trace-v2", challenge,
                                      struct.pack("<Q", sequence), struct.pack("<Q", trial))
                hit = wire_hash(b"ticket", challenge, candidate) <= header[118:150]
                require(hit is (trial == trials - 1), "omitted failed target trial")
            require(candidate == trace, "invented false trace")
            transactions = business[0]["transactions"]
            encoded = header + struct.pack("<H", len(transactions)) + b"".join(
                struct.pack("<H", len(tx)) + tx for tx in transactions) + prefix + trace
            digest = hashlib.sha256(encoded).hexdigest()
            require(digest == row["packet_sha256"] and digest not in all_packets, "whole-packet cache reuse")
            all_packets.add(digest)
            require(row["body_digest"] == body_digest({"op": "submit", "packet": encoded.hex()}), "unbound attack body")
            require(row["body_digest"] not in bodies, "duplicate attack identity")
            bodies[row["body_digest"]] = row
            calls.append(row)
    return calls, bodies, healthy


def observation_index(report, attack_bodies, honest_bodies):
    require(len(report["observations"]) == 2, "listener evidence")
    result, healthy = {}, True
    history_bodies = {row["body_digest"] for row in report["history"]}
    for listener, capture in enumerate(report["observations"]):
        snapshot = capture["snapshot"]
        require(natural(snapshot["capacity"]) and snapshot["capacity"] == 16384
                and len(snapshot["records"]) <= 16384, "observer bound")
        require(all(natural(snapshot[k]) for k in ("records_not_retained", "measurement_failures", "accepted_connections_seen"))
                and type(snapshot["counter_overflow"]) is bool, "observer counter types")
        complete = (snapshot["records_not_retained"] == snapshot["measurement_failures"] == 0
                    and snapshot["counter_overflow"] is False
                    and snapshot["accepted_connections_seen"] == len(snapshot["records"])
                    and all(r["complete"] is True and r["observation_failed"] is False for r in snapshot["records"]))
        require(capture["coverage_complete"] is complete, "observer coverage label")
        healthy &= complete
        for row in snapshot["records"]:
            key = (listener, row["connection_id"])
            require(key not in result and natural(row["connection_id"]), "duplicate receiver observation")
            result[key] = row
            require(row["operation"] is None or natural(row["operation"]), "native operation type")
            require(all(row[k] is None or natural(row[k]) for k in
                        ("dispatch_thread_cpu_ns", "full_work_thread_cpu_ns")), "native CPU counter type")
            if row["body_digest"] is not None:
                require(type(row["body_digest"]) is list and len(row["body_digest"]) == 32
                        and all(natural(b) and b <= 255 for b in row["body_digest"]),
                        "native body digest")
                digest = bytes(row["body_digest"]).hex()
                if digest in attack_bodies or digest in honest_bodies:
                    require(row["operation"] == 1, "Submit body under a different operation")
                elif digest in history_bodies:
                    require(row["operation"] == 3, "History body under a different operation")
                else:
                    raise ValueError("unassociated receiver body")
                if row["operation"] == 1:
                    require(digest in attack_bodies or digest in honest_bodies, "unassociated Submit observation")
                    if digest in attack_bodies:
                        require(row["full_work_accepted"] is not True and row["dispatch_accepted"] is not True,
                                "hostile native validation accepted")
    return result, healthy


def snapshot_keys(value, final_records, attack_bodies, round_start, round_end):
    require(round_start <= value["started_ns"] <= value["ended_ns"] <= round_end, "snapshot outside round")
    keys, paid = set(), 0
    for row in value["rejections"]:
        key = (row["listener"], row["connection_id"])
        require(key not in keys and key in final_records, "invented receiver progress")
        final = final_records[key]
        require(row["body_digest"] in attack_bodies
                and row["body_digest"] == bytes(final["body_digest"]).hex()
                and final["dispatch_accepted"] is False
                and row["dispatch_thread_cpu_ns"] == final["dispatch_thread_cpu_ns"], "hostile progress provenance")
        keys.add(key)
        if natural(row["dispatch_thread_cpu_ns"]):
            paid += row["dispatch_thread_cpu_ns"]
    return keys, paid


def check_phase(report, business):
    require(all(natural(report[k]) for k in ("window_ns", "listeners", "ready_actors")),
            "integer phase resource envelope")
    require(report["schema"] == SCHEMA and report["phase"] in PHASES and report["window_ns"] == WINDOW,
            "phase namespace/window")
    policy(report["policy"])
    no_authority(report)
    require(report["listeners"] == 2 and report["shared_cpu_domain"] is True, "split CPU budget")
    require(report["ready_actors"] == (0 if report["phase"] == "baseline" else ATTACKERS), "pre-start readiness")
    budget(report["initial_budget"])
    require(report["initial_budget"]["stored_credit_ns"] == report["initial_budget"]["in_flight"] == 0,
            "cold startup minted credit")
    flow(report["initial_flow"], settled=True)
    require(report["initial_flow"]["credited_refill_ns"] == report["initial_flow"]["paid_cpu_debit_ns"] == 0,
            "preparation warmed cold CPU epoch")
    memory = report["initial_admission"]["retained_software_bytes"]
    require(natural(memory) and 0 < memory <= 4 * 1024 * 1024, "missing or expanded cache storage size")
    admission(report["initial_admission"], memory)
    require(report["initial_admission"]["registered"] == 0, "reused admission epoch")
    budget(report["final_budget"])
    settled = flow(report["final_flow"], settled=True)
    admission(report["final_admission"], memory)
    require(report["final_admission"]["waiting"] == 0, "leaked FIFO position")
    if settled:
        require(report["final_flow"]["stored_credit_ns"] == report["final_budget"]["stored_credit_ns"],
                "final budget/flow mismatch")
    samples, prior_end = report["samples"], 0
    require(0 < len(samples) <= 600, "sample bound")
    for sample in samples:
        require(natural(sample["started_ns"]) and natural(sample["ended_ns"])
                and prior_end <= sample["started_ns"] < WINDOW
                and sample["started_ns"] <= sample["ended_ns"], "sample clock order")
        prior_end = sample["ended_ns"]
        budget(sample["budget"])
        flow(sample["flow"])
        admission(sample["admission"], memory)
        require(natural(sample["clock_failures"]), "CPU clock failure counter")
        require(sample["depleted"] is depleted(sample),
                "reservation-only, stale-refill or invented depletion")
    attacks, attack_bodies, actors_healthy = attack_calls(report, business)
    honest_bodies = {p["body"] for p in business}
    records, coverage = observation_index(report, attack_bodies, honest_bodies)
    accepted_indices = set()
    require(len(report["submissions"]) <= 128 and len(report["history"]) <= 64, "honest call cap")
    for row in report["submissions"]:
        index = row["packet_index"]
        require(type(index) is int and 0 <= index < 21 and row["body_digest"] == business[index]["body"],
                "honest packet association")
        if call(row):
            accepted_indices.add(index)
    for row in report["history"]:
        require(row["request"]["op"] == "history" and row["body_digest"] == body_digest(row["request"]),
                "History association")
        call(row)
        for key in ("client_import", "client_confirmation"):
            if key in row:
                require(natural(row[key]["started_ns"]) and natural(row[key]["ended_ns"])
                        and row[key]["started_ns"] <= row[key]["ended_ns"], "client verification clock")
    round_reports = []
    require(len(report["rounds"]) <= ROUNDS, "round cap")
    for index, row in enumerate(report["rounds"]):
        a, b = row["started_ns"], row["ended_ns"]
        require(natural(row["round"]) and natural(row["scheduled_ns"])
                and row["round"] == index and row["scheduled_ns"] == 1_000_000_000 + index * 4_000_000_000
                and natural(a) and natural(b) and row["scheduled_ns"] <= a <= b, "round schedule")
        tip = business[(index + 1) * 7 - 1]["id"]
        require(row["tip"] == tip and row["included_block"] == business[index * 7]["id"]
                and row["transaction"] == wire_hash(b"tx-id", business[index * 7]["transactions"][0]).hex(),
                "business confirmation identity")
        value = row["observation"]
        if value is not None:
            require(type(value) is dict and all(type(value[k]) is bool for k in
                    ("confirmed", "finalized", "execution_authority", "reorged")),
                    "native observation boolean fields")
            require(value["transaction"] == row["transaction"]
                    and value["included_block"] == row["included_block"]
                    and value["observed_tip"] == row["tip"]
                    and value["network"] == business[index * 7]["header"][6:38].hex()
                    and value["parameters"] == business[index * 7]["header"][38:70].hex(),
                    "native observation identity/context association")
            require(natural(value["included_height"]) and natural(value["observed_height"])
                    and value["included_height"] == business[index * 7]["height"]
                    and value["observed_height"] == business[(index + 1) * 7 - 1]["height"],
                    "native observation height association")
            require(not (value["confirmed"] and value["reorged"]), "contradictory native confirmation/reorg")
        confirmed = (value is not None and value["confirmed"] is True and value["finalized"] is False
                     and value["execution_authority"] is False and value["reorged"] is False
                     and type(value["depth"]) is int
                     and value["depth"] == 6 and b < WINDOW)
        require(row["confirmed_inside_pressure_window"] is confirmed, "late or invented confirmation")
        on_time_submissions = set(range(index * 7, (index + 1) * 7)) <= accepted_indices
        history_completions = [h for h in report["history"] if
                        h.get("client_confirmation", {}).get("succeeded") is True
                        and h["request"]["tip"] == tip and a <= h["client_import"]["started_ns"]
                        <= h["client_import"]["ended_ns"] <= h["client_confirmation"]["started_ns"]
                        <= h["client_confirmation"]["ended_ns"] <= b
                        and h["client_import"]["succeeded"] is True]
        if confirmed:
            require(bool(history_completions), "confirmation bypassed independent History replay")
        verified_history = any(call(h) for h in history_completions)
        before, before_cpu = snapshot_keys(row["hostile_before"], records, attack_bodies, a, b)
        after, after_cpu = snapshot_keys(row["hostile_after"], records, attack_bodies, a, b)
        require(before <= after and row["hostile_before"]["ended_ns"] <= row["hostile_after"]["started_ns"],
                "receiver progress reversed")
        # Physical timeout/cancellation tails remain in the evidence. They are
        # not extended request lifetimes for establishing attack-call overlap.
        overlap = sum(c["started_ns"] < b and min(c["ended_ns"], c["deadline_ns"]) > a for c in attacks)
        physical_overlap = sum(c["started_ns"] < b and c["ended_ns"] > a for c in attacks)
        exhaustion = any(a <= s["started_ns"] <= s["ended_ns"] <= b and depleted(s) for s in samples)
        require(natural(row["overlapping_attack_calls"]) and row["overlapping_attack_calls"] == overlap
                and row["depletion_observed_during_round"] is exhaustion, "aggregate-only overlap claim")
        round_reports.append({"round": index, "confirmed": confirmed,
                              "seven_submissions_inside_original_call_deadlines": on_time_submissions,
                              "on_time_history_and_independent_verification": bool(verified_history),
                              "qualified_confirmation": bool(confirmed and on_time_submissions and verified_history),
                              "attack_calls_overlapping": overlap,
                              "attack_calls_including_physical_tails_overlapping": physical_overlap,
                              "new_receiver_hostile_rejections": len(after - before),
                              "receiver_hostile_dispatch_cpu_increase_ns": after_cpu - before_cpu,
                              "paid_depletion_inside_round": exhaustion,
                              "actual_pressure_overlap": overlap > 0 and len(after - before) > 0 and after_cpu > before_cpu})
    services = report["services"]
    require(len(services) == 2, "service join coverage")
    require(all(not isinstance(s.get("Ok"), dict) or natural(s["Ok"]["mutation_cpu_clock_failures"])
                for s in services), "service CPU clock counter type")
    services_healthy = all(isinstance(s.get("Ok"), dict)
                           and s["Ok"]["mutation_cpu_clock_failures"] == 0 for s in services)
    honest_full_work = {bytes(r["body_digest"]).hex() for r in records.values()
                        if r["full_work_accepted"] is True and r["body_digest"] is not None
                        and natural(r["full_work_thread_cpu_ns"]) and r["full_work_thread_cpu_ns"] > 0}
    fresh_published, cache_hits, transcript_entries, transcript_completed, no_arithmetic_observation = set(), 0, 0, 0, 0
    for record in records.values():
        if record["body_digest"] is None:
            continue
        digest = bytes(record["body_digest"]).hex()
        if digest not in attack_bodies:
            continue
        work = record.get("work_arithmetic")
        if work is None or work["completed"] is not True or work["arithmetic"] is None:
            no_arithmetic_observation += 1
            continue
        require(natural(work["slots"]) and natural(work["retained_software_bytes"])
                and work["slots"] == 64 and work["retained_software_bytes"] == memory, "request cache owner changed")
        facts = work["arithmetic"]
        cache_hits += facts["exact_fact_found"] is True
        transcript_entries += facts["transcript_entered"] is True
        transcript_completed += facts["transcript_completed"] is True
        if (facts["exact_fact_found"] is False and facts["transcript_completed"] is True
                and facts["transcript_entered"] is True and facts["publication"] in ("trace", "product")):
            header = raw_hex(attack_bodies[digest]["header"], 318)
            fresh_published.add(wire_hash(b"challenge", header).hex())
    churn_required = report["phase"] == "correct-product-false-trace"
    churn_observed = len(fresh_published) >= 65
    churn = not churn_required or churn_observed
    heights = {business[0]["header"][70:102].hex(): business[0]["height"] - 1}
    heights.update({packet["id"]: packet["height"] for packet in business})
    for owner in ("receiver", "client"):
        require(natural(report[owner + "_height"]) and natural(report[owner + "_generation"])
                and report[owner + "_generation"] <= U64_MAX, "native height/generation type")
        require(report[owner + "_tip"] in heights
                and report[owner + "_height"] == heights[report[owner + "_tip"]],
                "active block height association; activation generation is not height")
    service = (len(round_reports) == ROUNDS and all(r["qualified_confirmation"] for r in round_reports)
               and report["receiver_tip"] == report["client_tip"] == business[-1]["id"]
               and report["receiver_height"] == report["client_height"] == 25
               and honest_bodies <= honest_full_work and coverage and services_healthy and settled
               and report["final_budget"]["accounting_unavailable"] is False
               and report["final_budget"]["in_flight"] == 0 and not report["errors"])
    pressure = report["phase"] == "baseline" or (actors_healthy and churn
               and len(round_reports) == ROUNDS and all(r["actual_pressure_overlap"] for r in round_reports)
               and any(r["paid_depletion_inside_round"] for r in round_reports))
    return {"phase": report["phase"], "service_qualified": bool(service),
            "pressure_and_depletion_required": report["phase"] != "baseline",
            "pressure_and_depletion_qualified": bool(pressure),
            "finite_qualification": bool(service and pressure), "rounds": round_reports,
            "attack_calls": len(attacks), "actors_healthy": bool(actors_healthy),
            "fresh_challenges_actually_published": len(fresh_published),
            "arithmetic_fact_hits": cache_hits,
            "attack_transcript_entries": transcript_entries,
            "attack_transcripts_completed": transcript_completed,
            "attack_observations_without_completed_arithmetic": no_arithmetic_observation,
            "fixed_64_slot_churn_required": churn_required,
            "fixed_64_slot_churn_qualified": churn_observed,
            "actual_paid_cpu_ns": report["final_flow"]["paid_cpu_debit_ns"] if settled else None,
            "depletion_basis": "same-lock flow with original refill projection and full-sample-interval upper bound; not continuous whole-round exhaustion",
            "depletion_samples": sum(depleted(s) for s in samples)}


def check(manifest, prepared, phases):
    require(all(natural(manifest[k]) for k in ("window_ns", "attackers", "actor_call_cap", "rounds")),
            "integer campaign resource envelope")
    require(manifest["schema"] == SCHEMA and manifest["window_ns"] == WINDOW
            and manifest["attackers"] == ATTACKERS and manifest["actor_call_cap"] == CALL_CAP
            and manifest["rounds"] == ROUNDS, "campaign envelope")
    policy(manifest["policy"])
    no_authority(manifest)
    require([p["phase"] for p in manifest["phases"]] == list(PHASES)
            and [p["file"] for p in manifest["phases"]] == [p + ".json" for p in PHASES], "phase coverage")
    business = preparation(prepared)
    require(len(phases) == 3, "missing phase")
    reports, epochs = [], set()
    for name, phase in zip(PHASES, phases):
        require(phase["phase"] == name and phase["policy"] == manifest["policy"], "phase/profile binding")
        epoch = phase["epoch_monotonic_ns"]
        require(natural(epoch) and epoch not in epochs, "cold epochs reused")
        epochs.add(epoch)
        report = check_phase(phase, business)
        all_confirmed = len(report["rounds"]) == ROUNDS and all(r["confirmed"] for r in report["rounds"])
        require(manifest["phases"][len(reports)]["all_rounds_confirmed"] is all_confirmed,
                "manifest hid failed confirmation")
        reports.append(report)
    qualified = all(p["finite_qualification"] for p in reports)
    return {"schema": "pon-pure-pressure-qualification-v3", "input_consistent": True,
            "finite_qualification": qualified, "phases": reports,
            "public_fairness_qualified": False, "production_qualified": False,
            "work_hardness_qualified": False, "installation_authorized": False,
            "scope": "Fixed 24-actor, two-listener, shared cold CPU epoch; 30s phases and original 2s calls. Local monotonic clocks and CPU observations, not authenticity, unlimited-Sybil fairness, WAN throughput, work hardness or installation authority."}


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    require(len(raw) <= MAX_FILE_BYTES and raw.endswith(b"\n"), "bounded complete evidence file")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def finite_number(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite JSON number")
        return value

    def invalid_constant(_):
        raise ValueError("nonfinite JSON constant")

    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_float=finite_number, parse_constant=invalid_constant)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    try:
        result = check(load(args.directory / "campaign.json"), load(args.directory / "preparation.json"),
                       [load(args.directory / (p + ".json")) for p in PHASES])
    except (ValueError, KeyError, TypeError, OSError) as error:
        result = {"schema": "pon-pure-pressure-qualification-v3", "input_consistent": False,
                  "finite_qualification": False, "error": str(error),
                  "public_fairness_qualified": False, "production_qualified": False,
                  "work_hardness_qualified": False, "installation_authorized": False}
    raw = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
    print(raw, end="")
    return 0 if result["input_consistent"] and (not args.require_qualified or result["finite_qualification"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
