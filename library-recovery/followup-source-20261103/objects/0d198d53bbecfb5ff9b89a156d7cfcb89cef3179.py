#!/usr/bin/env python3
"""Read-only profile/rejection audit; no native tests or CI are launched.

Requires paired ZIP 12889490469, the pinned source tree, and the sibling
audit_history_96f_paid_credit.py module. Complements its existing receipt;
does not modify that receipt or reinterpret campaign failure as success.
"""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import statistics
import zipfile

import audit_history_96f_paid_credit as base


EXTRA_SOURCE = {
    "trillionnium/crates/trnm-pon-node/tests/support/multiprocess_work.rs": "01779c93ddc8ca61923588f534a3bf88c9e5ad9f",
    "trillionnium/crates/trnm-pon-node/src/store.rs": "daea2b34f04b4e6b2359e70ec379589b00ce1d91",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs": "ddea33f9d22940d4be382efccc4eb83dc5cb0efd",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, default=base.ROOT)
    parser.add_argument("--source-dir", type=Path, default=base.ROOT.parent / "repo")
    parser.add_argument("--output", type=Path,
                        default=base.ROOT / "history-96f-attack-profile-and-rejection-audit.json")
    args = parser.parse_args()
    sources, constants = base.source_audit(args.source_dir)
    for path, expected in EXTRA_SOURCE.items():
        data = (args.source_dir / path).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        base.require(blob == expected, "source Git blob: " + path)
        sources.append({"path": path, "git_blob": blob, "sha256": hashlib.sha256(data).hexdigest()})
    path = args.artifacts_dir / base.ARCHIVES["paired"][0]
    base.require(base.sha_file(path) == base.ARCHIVES["paired"][1], "paired archive SHA256")
    rows, all_trials = [], []
    with zipfile.ZipFile(path) as archive:
        for number in range(1, 4):
            for mode, error in [("from-zero", "Transcript"), ("late-product", "Product")]:
                member = f"n8/run-{number}-raw/{mode}.json"
                phase, member_sha = base.read(archive, member)
                expected_policy = {"schema": "public-protected-resource-policy-observation-v1",
                    "transport_profile": "public-protected-development-v3", "policy_id": base.POLICY,
                    "ticket_bits": 8, "lifetime_ms": 2000}
                base.require(phase["public_resource_policy"] == expected_policy, "exact 8-bit public policy")
                actors = [child["report"]["result"] for child in phase["children"]]
                base.require(len(actors) == 24, "24 original actors")
                for worker in range(24):
                    job, _ = base.read(archive, f"n8/run-{number}-raw/{mode}/attacker-{worker:02}/job.json")
                    base.require("work_profile" not in job and "public_resource_policy" not in job,
                                 "original raw actor binding")
                    base.require(len(job["transactions"]) == 1, "real signed business transaction retained")
                base.require(all(a["acquisition"]["diagnostic_result"] == {"Err": error}
                                 and a["acquisition"]["relation_rejection_matches_mode"] for a in actors),
                             "24 acquisition rejection diagnostics")
                hostile_digests = {a["acquisition"]["public_request_body_digest"] for a in actors}
                calls = [call for actor in actors for call in actor["calls"]]
                refused = [call for call in calls if call["status"] == "refused"]
                base.require(all(call["response"]["value"].get("error") == "WORK:" + error for call in refused),
                             "all signed refusal responses use the expected W1 error")
                base.require(all(call["metrics"]["solution_found"]
                                 and call["metrics"]["solution_trials"] >= 1
                                 and call["metrics"]["solution_trials"] == call["response"]["solve_trials"]
                                 for call in refused), "actual nonzero admission nonce-search receipts")
                trials = [call["metrics"]["solution_trials"] for call in refused]
                all_trials.extend(trials)
                records = [record for record in phase["receiver_observation"]["records"]
                           if base.digest_hex(record["body_digest"]) in hostile_digests
                           and record["dispatch_started"]]
                for record in records:
                    base.require(record["full_work_started"] and not record["full_work_accepted"]
                                 and record["full_work_thread_cpu_ns"] > 0,
                                 "every paid hostile dispatch performs native work")
                    stages = {stage["phase"]: stage for stage in record["submit_phases"]}
                    for stage in ["decode", "context", "work"]:
                        base.require(stages[stage]["started"] and stages[stage]["completed"],
                                     "completed native phase: " + stage)
                    base.require(stages["decode"]["accepted"] and stages["context"]["accepted"]
                                 and stages["work"]["accepted"] is False
                                 and not stages["admission"]["started"], "W1 rejection boundary")
                metrics = phase["service_outcome"]["Ok"]
                base.require(metrics["ticket_refusals"] == metrics["signature_refusals"]
                             == metrics["replay_refusals"] == 0, "not transport signature/ticket/replay rejection")
                base.require(phase["completion_work_observation"]["live_completions"]
                             == phase["completion_work_observation"]["repeated_identity_skips"] == 0,
                             "no completion-identity shortcut")
                mean_paid = statistics.mean(record["dispatch_thread_cpu_ns"] for record in records)
                rows.append({"member": member, "member_sha256": member_sha,
                    "round": number, "mode": mode, "public_resource_policy": expected_policy,
                    "actor_job_raw_profile_bindings_checked": 24,
                    "acquisition_diagnostics": {error: len(actors)},
                    "signed_refusal_responses": len(refused), "signed_refusal_code": "WORK:" + error,
                    "solution_trials": {"count": len(trials), "sum": sum(trials), "min": min(trials),
                        "mean": statistics.mean(trials), "max": max(trials), "zeros": trials.count(0)},
                    "mean_solution_search_ns": statistics.mean(call["metrics"]["solution_search_ns"] for call in refused),
                    "paid_hostile_dispatch_count": len(records),
                    "all_paid_hostile_decode_context_accepted_work_completed_and_rejected": True,
                    "all_paid_hostile_admission_not_started": True,
                    "mean_paid_hostile_dispatch_cpu_ns": mean_paid,
                    "mean_full_native_work_cpu_ns": statistics.mean(record["full_work_thread_cpu_ns"] for record in records),
                    "hypothetical_hostile_debit_cpu_ns_per_second_at_128_dispatches": mean_paid * 128,
                    "hypothetical_cost_rate_below_refill": mean_paid * 128 < constants["MUTATION_CPU_REFILL_NS_PER_SECOND"],
                    "rate_scope": "Observed average cost multiplied by the challenge policy rate; not a bound on any other input or a prediction of altered scheduling. Read/honest requests share the rate.",
                    "service_refusals": {k: metrics[k] for k in ["ticket_refusals", "signature_refusals", "replay_refusals", "parse_refusals"]},
                    "completion_live_completions": 0, "completion_repeated_identity_skips": 0})
    report = {
        "schema": "history-96f-attack-profile-and-rejection-audit-v1",
        "head": base.HEAD, "tree": base.TREE, "run": 40852779415,
        "archive": {"filename": path.name, "sha256": base.ARCHIVES["paired"][1]},
        "pinned_source_files": sources,
        "admission": {"actual_transport_profile": "public-protected-development-v3",
            "actual_work_profile": "RawR13", "actual_ticket_bits": 8, "actual_lifetime_ms": 2000,
            "min_pow_bits_named_field_present_in_this_configuration": False,
            "explanation": "This revision uses PublicPolicy.bits/ticket_bits, not a min_pow_bits field. PublicPolicy::new permits 8..20 and the campaign fixes bits=8. No zero-bit or pure-PoN conclusion follows.",
            "hash_domain": "public-ticket-v3", "nonce_search_limit": 1048576,
            "all_signed_refusal_solution_trials": {"count": len(all_trials), "sum": sum(all_trials),
                "min": min(all_trials), "mean": statistics.mean(all_trials), "max": max(all_trials)}},
        "w1": {"profile": "pon-matmul-transcript-64-v1", "kernel": "production-transposed",
            "from_zero": "Canonical maintenance A/B and a searched fake trace that meets target; complete transcript replay then Transcript mismatch; skips subsequent product completion.",
            "late_product": "Legal producer/search for the actual business-header challenge/target; change claimed product C[0] by +1 modulo q, retaining the valid trace. Canonical/task/target checks, entire transcript replay and product completion run, then final Product relation rejects.",
            "late_product_is_last_claimed_cell_mismatch": False,
            "late_product_comparison_caveat": "C[0] is changed, so comparison may fail at the first changed bytes; this is complete arithmetic before the final product relation, not a claim to measure a mismatch in the last serialized product cell.",
            "raw_service_rejection_cache_enabled": False, "raw_service_arithmetic_facts_enabled": False,
            "real_context": "Attack jobs use business[0] header and its real signed transaction after 1024 signed seed transfers; only header nonce/search and invalid work proof are varied. Native decode/context stages actually accepted every paid hostile dispatch.",
            "signature_scope": "Native protected client signs its cookie solution and verifies the server response. This audit checks retained native observations and source, not a new independent cryptographic signature replay."},
        "phases": rows,
        "append_case_recommendation": "Do not add a duplicate complete-W1-terminal-invalid case: late-product already supplies it under the original constraints. Preserve the current red campaign.",
        "existing_entry_points": [
            "public_v3_multiprocess::separate_process_graph_resource_fence_v1_work_and_signed_confirmation_campaign",
            "public_v3_multiprocess::separate_process_work_and_signed_confirmation_campaign",
            "public_v3_multiprocess::independent_hostile_construction_preserves_exact_rejection_stage_and_misses"],
        "limits": ["No native execution or CI started in this audit.",
            "Original failures, input mix, budgets, admission PoW and resource limits remain unchanged.",
            "The existing pon_rejection_cost example separately contains product-last-cell; its component result is not this History hosted campaign.",
            "Two phases have one parse refusal among all connections; all retained paid hostile dispatches nevertheless pass decode/context and fail the work relation. Other deadline errors must not be relabeled W1 rejections."]}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"audit": "PASS", "output": str(args.output), "sha256": base.sha_file(args.output),
        "phases": len(rows), "signed_refusals": len(all_trials), "solution_trials": sum(all_trials),
        "paid_hostile_dispatches": sum(row["paid_hostile_dispatch_count"] for row in rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
