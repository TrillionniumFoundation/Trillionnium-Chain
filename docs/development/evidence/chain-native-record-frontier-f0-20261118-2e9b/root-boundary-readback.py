#!/usr/bin/env python3
"""Read the actual ROOT Submit/History boundary and original receiver accounting."""
import argparse, collections, hashlib, json, pathlib, sys, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[4]
HEAD = "d95239eda6a666458aa264ddeaf993d6d9fbf37d"
ZIP_SHA256 = "b4457d8062f6f5068286c8b597668b09065a5eb2f12c85759517037cb386be93"
REPORT_SHA256 = "2d7041b82c29226a56300f7e0a52c6262d76175226d7a77309ed20459508318b"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def body(value):
    if isinstance(value, str):
        try:
            decoded = bytes.fromhex(value)
            return decoded.hex() if len(decoded) == 32 else None
        except ValueError:
            return None
    if isinstance(value, list) and len(value) == 32 and all(type(x) is int and 0 <= x < 256 for x in value):
        return bytes(value).hex()
    return None

def sum_known(rows, key):
    values = [r.get(key) for r in rows]
    known = [v for v in values if type(v) is int and v >= 0]
    return {"known_sum": sum(known), "rows": len(rows), "unknown_rows": len(rows)-len(known),
            "complete_observed_sum": sum(known) if len(known) == len(rows) else None}

def bounded(value):
    raw = json.dumps(value, sort_keys=True).encode()
    if len(raw) <= 1800:
        return value
    return {"original_value_bytes": len(raw), "original_value_sha256": sha(raw),
            "full_value_retained_in_original_report": True}

def group(rows):
    phases = collections.defaultdict(list)
    for row in rows:
        for phase in row.get("submit_phases", []):
            phases[phase["phase"]].append(phase)
    dispatched = [r for r in rows if r.get("operation") == 1 and r.get("dispatch_started") is True]
    return {"records": len(rows),
            "operation_counts": dict(collections.Counter(str(r.get("operation")) for r in rows)),
            "dispatch_started": len(dispatched),
            "dispatch_accepted": sum(r.get("dispatch_accepted") is True for r in rows),
            "actual_dispatch_error_codes": dict(collections.Counter(str(r.get("dispatch_error_code")) for r in rows)),
            "actual_terminal_error_codes": dict(collections.Counter(str(r.get("terminal_error_code")) for r in rows)),
            "full_work_started": sum(r.get("full_work_started") is True for r in rows),
            "full_work_accepted": sum(r.get("full_work_accepted") is True for r in rows),
            "original_dispatch_owner_cpu": sum_known(dispatched, "dispatch_thread_cpu_ns"),
            "nested_submit_phase_cpu": {name: sum_known(values, "thread_cpu_ns") for name,values in phases.items()},
            "examples": [{key: bounded(row.get(key)) for key in (
                "connection_id", "body_digest", "operation", "dispatch_started", "dispatch_accepted",
                "dispatch_error_code", "terminal_phase", "terminal_error_code",
                "grant_wait", "paid_task_queue_wait", "challenge_wait", "response_write",
                "error_timing", "cancellation", "submit_phases", "dispatch_thread_cpu_ns"
            )} for row in rows[:2]],
            "scope": "Actual records matched by exact original wire body digest. Phase CPU is nested; do not add it to owner CPU. Waiting observations may overlap."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=pathlib.Path, required=True)
    parser.add_argument("--readback", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    raw = args.archive.read_bytes()
    assert sha(raw) == ZIP_SHA256 and len(raw) == 18089290
    checked = json.loads(args.readback.read_text())
    assert checked["run_id"] == 44376853052 and checked["head"] == HEAD
    assert checked["archive_sha256"] == ZIP_SHA256 and checked["manifest_files_checked"] == 443
    pins = checked["original_reader_source_sha256"]
    assert len(pins) == 12
    for name,expected in pins.items():
        assert sha((ROOT/name).read_bytes()) == expected, name
    sys.path.insert(0, str(ROOT/"scripts"))
    sys.path.insert(0, str(ROOT/"scripts/ci"))
    import run_fixed_host_root_f0 as f0
    with zipfile.ZipFile(args.archive) as archive:
        raw_report = archive.read("execution/raw/report.json")
        assert sha(raw_report) == REPORT_SHA256
        report = json.loads(raw_report)
    phase = report["phases"][1]
    assert phase["mode"] == "valid-work-root"
    observer = phase["receiver_observation"]
    records = observer["records"]
    hostile = {body(row["public_request_body_digest"]) for row in phase["root_supplement"]["acquisitions"]}
    assert None not in hostile and len(hostile) == 24
    hostile_rows = [r for r in records if body(r.get("body_digest")) in hostile]
    other_rows = [r for r in records if body(r.get("body_digest")) not in hostile]
    submissions = phase["submissions"]
    projected = []
    for row in submissions:
        item = {key: row.get(key) for key in (
            "packet_index", "height", "started_ns", "ended_ns", "status", "error",
            "returned_after_window", "public_request_body_digest"
        )}
        response = row.get("response")
        if isinstance(response, dict):
            item["response_ok"] = response.get("ok")
            value = response.get("value")
            if isinstance(value, dict):
                item["response_error"] = value.get("error")
        projected.append(item)
    next_packet = 0
    for row in submissions:
        assert row["packet_index"] == next_packet
        if row["status"] == "ok" and row["returned_after_window"] is False:
            next_packet += 1
    assert next_packet == 5 and len(phase["history"]) == 0
    samples = []
    for row in phase["budget_samples"]:
        value = row.get("meter", {}).get("Ok")
        if not isinstance(value, dict):
            continue
        flow = value.get("actual_flow")
        if not isinstance(flow, dict):
            continue
        samples.append({"at_ns": row["at_ns"], "observation_started_ns": row["observation_started_ns"],
                        "observation_ended_ns": row["observation_ended_ns"],
                        "depleted": value["depleted"],
                        "balance_identity_verified": flow["balance_identity_verified"],
                        "remaining_paid_credit_ns": flow["remaining_paid_credit_ns"],
                        "paid_cpu_debit_ns": flow["paid_cpu_debit_ns"],
                        "credited_refill_ns": flow["credited_refill_ns"],
                        "discarded_refill_ns": flow["discarded_refill_ns"],
                        "booked_reservation_ns": flow["booked_reservation_ns"],
                        "live_owners": flow["live_owners"]})
    credits = [row["remaining_paid_credit_ns"] for row in samples if type(row["remaining_paid_credit_ns"]) is int]
    try:
        root_depletion = f0.checked_depletion_samples(phase)
        depletion_refusal = None
    except ValueError as error:
        # Retain the ORIGINAL refusal. A missing qualification is not an empty
        # successful interval list and cannot become a passed pressure gate.
        assert str(error) == "NUMERIC_DEPLETION_REQUIRED", str(error)
        root_depletion = None
        depletion_refusal = str(error)
    active = [r for r in records if r.get("operation") == 1 and r.get("dispatch_started") is True]
    actual_cpu = sum_known(active, "dispatch_thread_cpu_ns")
    flow = phase["final_actual_flow"]
    original_owner_equal = (actual_cpu["complete_observed_sum"] == flow["paid_cpu_debit_ns"]
                            == flow["settled_full_cpu_ns"]
                            == phase["root_supplement"]["mutation_owner_cpu_ns"]
                            == phase["service_outcome"]["Ok"]["mutation_cpu_charged_ns"])
    result = {
        "schema": "chain-frontier-root-boundary-readback-v1", "run_id": 44376853052,
        "head": HEAD, "archive_sha256": ZIP_SHA256, "report_sha256": REPORT_SHA256,
        "independent_readback_sha256": sha(args.readback.read_bytes()),
        "reader_source_sha256": sha(pathlib.Path(__file__).read_bytes()),
        "planned_first_round_business_packets": 7, "next_packet_at_window_end": next_packet,
        "actual_submission_attempts": len(submissions), "actual_submission_field_names": sorted({k for r in submissions for k in r}),
        "actual_submissions": projected, "actual_history_calls": len(phase["history"]),
        "actual_client_imports": sum(r.get("client_import") is not None for r in phase["history"]),
        "source_boundary": {
            "file": "trillionnium/crates/trnm-pon-node/tests/support/multiprocess_root_phase_host.rs",
            "source_commit": HEAD, "submit_loop_line": 621, "history_loop_line": 644,
            "condition": "next == final_index && monotonic() < end && history.len() < 64",
            "conclusion": "The actual first seven-Submit frontier was not reached; this ROOT phase issued no History request."},
        "receiver_observer_complete": phase["observer_complete"],
        "receiver_records": len(records), "receiver_records_not_retained": observer["records_not_retained"],
        "receiver_measurement_failures": observer["measurement_failures"],
        "original_hostile_bodies": len(hostile), "hostile_original_body_records": group(hostile_rows),
        "other_observed_body_records": group(other_rows),
        "original_dispatch_owner_cpu": actual_cpu,
        "original_paid_cpu_identity_matches": original_owner_equal,
        "final_actual_flow": flow, "initial_meter": phase["initial_meter"],
        "original_genuine_budget_depletion_observed": phase["genuine_budget_depletion_observed"],
        "original_checked_depletion_intervals": root_depletion,
        "original_depletion_reader_refusal": depletion_refusal,
        "actual_paid_credit_samples": {
            "sample_count": len(samples), "all_balance_identities_verified": all(r["balance_identity_verified"] for r in samples),
            "depleted_samples": sum(r["depleted"] for r in samples),
            "minimum_observed_remaining_paid_credit_ns": min(credits) if credits else None,
            "maximum_observed_remaining_paid_credit_ns": max(credits) if credits else None,
            "first": samples[:1], "last": samples[-1:],
            "minimum_sample": min(samples, key=lambda r:r["remaining_paid_credit_ns"]) if samples else None,
            "scope": "Actual discrete samples only; not a continuous-time minimum or proof of impossibility."},
        "business_gate_pass": False, "complete_physical_cost_closed": False}
    assert result["receiver_observer_complete"] and observer["records_not_retained"] == 0 and observer["measurement_failures"] == 0
    assert original_owner_equal
    for name,expected in pins.items():
        assert sha((ROOT/name).read_bytes()) == expected, name
    with args.out.open("x") as target:
        json.dump(result, target, indent=2, sort_keys=True)
        target.write("\n")
    print(json.dumps({"run":44376853052, "submissions":len(submissions), "ack_frontier":next_packet,
                      "history_calls":0, "receiver_records":len(records),
                      "hostile_records":len(hostile_rows), "other_records":len(other_rows),
                      "paid_owner_cpu_ns":actual_cpu["complete_observed_sum"],
                      "minimum_observed_paid_credit_ns":min(credits) if credits else None,
                      "original_checked_depletion_intervals":None if root_depletion is None else len(root_depletion),
                      "original_depletion_reader_refusal":depletion_refusal,
                      "readback_sha256":sha(args.out.read_bytes())}))
if __name__ == "__main__":
    main()
