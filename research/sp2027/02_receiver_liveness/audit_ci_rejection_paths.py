#!/usr/bin/env python3
"""Read the immutable CI pair's native/cache path facts without executing it."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess


SOURCE = "8ebcdb01016946a131f9067ebe1ace39b9c4f260"
REPORT_SHA256 = "4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d"
SOURCE_PATHS = {
    "construction_and_pair": "trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs",
    "false_proof_prefix": "trillionnium/crates/trnm-pon-node/examples/support/w1_from_zero.rs",
    "service_dispatch": "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    "rejection_observer": "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_rejection.rs",
    "exact_rejection_cache": "trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs",
    "native_verifier": "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "error_mapping": "trillionnium/crates/trnm-pon-node/src/store.rs",
    "body_hash": "trillionnium/crates/trnm-protocol/src/pon_wire.rs",
    "host_contract": "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
}


def wire_hash(tag, value):
    """Exact pon_wire::hash framing for one byte slice, not a native verifier."""
    state = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    state.update(len(value).to_bytes(4, "little"))
    state.update(value)
    return state.hexdigest()


def sum_known(rows, field):
    values = [row[field] for row in rows]
    assert all(isinstance(value, int) and value >= 0 for value in values), field
    return sum(values)


def describe(rows, packet_by_digest):
    return {
        "count": len(rows),
        "connection_ids": [row["connection_id"] for row in rows],
        "full_work_thread_cpu_ns": sum_known(rows, "full_work_thread_cpu_ns"),
        "dispatch_thread_cpu_ns": sum_known(rows, "dispatch_thread_cpu_ns"),
        "packet_index_counts": dict(sorted(Counter(
            packet_by_digest[bytes(row["body_digest"]).hex()] for row in rows
        ).items())),
    }


def audit(report_path, source_repo):
    raw = report_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == REPORT_SHA256, "wrong raw report identity"
    report = json.loads(raw)
    assert report["schema"] == "public-v3-signed-confirmation-pressure-v1"
    baseline, pressure = report["phases"]
    assert baseline["workers"] == 0 and pressure["workers"] == 16
    assert baseline["requested_window_ns"] == pressure["requested_window_ns"] == 4_000_000_000

    source_files = {}
    for role, path in SOURCE_PATHS.items():
        data = subprocess.check_output(["git", "-C", str(source_repo), "show", SOURCE + ":" + path])
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        declared = subprocess.check_output([
            "git", "-C", str(source_repo), "rev-parse", SOURCE + ":" + path
        ], text=True).strip()
        assert blob == declared, path
        source_files[role] = {
            "path": path, "bytes": len(data), "git_blob": blob,
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/" + SOURCE + "/" + path,
        }

    packets = []
    packet_by_digest = {}
    for index, construction in enumerate(report["from_zero_construction"]):
        assert construction["status"] == "target_hit_unverified"
        body = json.dumps({"op": "submit", "packet": construction["packet"]}, separators=(",", ":")).encode()
        digest = wire_hash(b"public-request-body-v3", body)
        assert digest not in packet_by_digest
        packet_by_digest[digest] = index
        packets.append({
            "packet_index": index, "request_bytes": len(body),
            "server_body_digest": digest,
            "client_recorded_request_digest": wire_hash(b"pressure-recorded-request-v1", body),
        })
    assert len(packets) == 16

    attack_calls = [row for worker in pressure["attacks"] for row in worker["calls"]]
    transcript_calls = []
    call_outcomes = Counter()
    for call in attack_calls:
        value = (call.get("response") or {}).get("value", {})
        call_outcomes[(call["status"], value.get("error"), call.get("error"))] += 1
        packet = packets[call["packet_index"]]
        assert call["recorded_request_bytes"] == packet["request_bytes"]
        assert call["recorded_request_digest"] == packet["client_recorded_request_digest"]
        if call["status"] == "refused" and value.get("error") == "WORK:Transcript":
            transcript_calls.append(call)

    records = pressure["observations"]["records"]
    groups = {"native_transcript_replay": [], "cached_rejection": []}
    for row in records:
        diagnosis = (row.get("error_diagnostics") or {}).get("dispatch") or {}
        if diagnosis.get("message_prefix") != "WORK:Transcript":
            continue
        assert diagnosis["message_truncated"] is False
        assert row["complete"] is True and row["observation_failed"] is False
        assert bytes(row["body_digest"]).hex() in packet_by_digest
        assert row["full_work_started"] is True and row["full_work_accepted"] is False
        rejection = row["work_rejection"]
        assert rejection["completed"] is True
        cache = rejection["cache"]
        if cache["cached_rejection_returned"] is True:
            assert cache["exact_fact_found"] is True
            assert cache["native_verifier_started"] is False
            assert cache["native_verifier_returned"] is False
            assert cache["full_replay_started"] is False
            assert cache["publication"] == "none"
            groups["cached_rejection"].append(row)
        else:
            assert cache["native_verifier_started"] is True
            assert cache["native_verifier_returned"] is True
            assert cache["full_replay_started"] is True
            assert cache["publication"] == "retained"
            groups["native_transcript_replay"].append(row)

    counted = sum(len(group) for group in groups.values())
    assert counted == len(transcript_calls)
    assert pressure["observations"]["records_not_retained"] == 0
    assert pressure["observations"]["measurement_failures"] == 0
    assert not pressure["observations"]["counter_overflow"]
    return {
        "schema": "sp27-02-ci-rejection-path-audit-v1",
        "source_commit": SOURCE, "source_files": source_files,
        "raw_report_member": "from-zero-native/confirmation/report.json",
        "raw_report_bytes": len(raw), "raw_report_sha256": REPORT_SHA256,
        "artifact_id": 13871459353, "run_id": 43052900246, "job_id": 130634539770,
        "artifact_sha256": "8b21d753e0ac85ffdca7bc3e0a5f953d4dfffb24c7a10cc9ae394dcfe6590307",
        "attack_calls": len(attack_calls), "transcript_client_refusals": len(transcript_calls),
        "observer_records": len(records), "transcript_observer_records": counted,
        "client_outcomes": [
            {"status": status, "response_error": refusal, "call_error": error, "count": count}
            for (status, refusal, error), count in sorted(call_outcomes.items(), key=lambda item: str(item[0]))
        ],
        "all_transcript_records_bound_to_original_false_packets": True,
        "binding_scope": "request bytes and domain-separated body digests bind each record to one of 16 original false packets; repeated same-body calls are not uniquely paired across client/server clocks",
        "packets": packets,
        "groups": {name: describe(rows, packet_by_digest) for name, rows in groups.items()},
        "cpu_scope": "actual recorded calling-thread intervals; full_work is nested in dispatch and includes cache/cheap checks; neither column is additive to its parent",
        "native_stage_inference": "Exact source plus native verifier returned WORK:Transcript places 52 calls after complete transcript replay/digest comparison, before product correction and VerifiedWork; this is not a new execution or per-tile trace",
        "cached_stage_inference": "318 exact negative facts returned after current context and cache-key checks plus the original cancellation checkpoint, without native arithmetic replay",
        "mechanism_status": "UNKNOWN",
        "claims_not_established": [
            "370 full expensive arithmetic replays", "mutation CPU credit exhaustion",
            "replay cost caused the business deadline miss", "exclusive physical CPU allocation",
            "independently replicated healthy baseline", "fresh proof per attack call",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.report, args.source_repo)
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    with args.output.open("xb") as output:
        output.write(encoded)
    args.output.chmod(0o444)
    print(json.dumps({
        "output": str(args.output), "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "counts": {name: group["count"] for name, group in result["groups"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
