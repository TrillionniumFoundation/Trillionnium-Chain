#!/usr/bin/env python3
"""Read-only accounting diagnosis for the six same-host N8 attack phases.

Requires the original paired artifact 12889490469 and original N8 artifact
12888322275 ZIPs. Also requires the five pinned runtime/test source files from
the c571/96f source tree. Does not run Rust, replay work, or change any gate.
The original N8 artifact is only a counterexample to policy-wide impossibility;
its different host/binary is not a matched performance comparison.
"""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import statistics
import zipfile


ROOT = Path(__file__).resolve().parent
HEAD = "96f5e502d677fa37d53e0241208ce228a913d907"
TREE = "d2581b3fd4fc0c5cb8fdfab4d695a0b3698cc986"
POLICY = "c110c3ccb1e229c3a85f4819b1e087fa819c865b50f8bd3ab78d3b8f45206cb2"
ARCHIVES = {
    "paired": ("history-96f-12889490469.zip", "ffb51184690a57f41f913d7358b32de1f49e40503737c7ff4db2459bd4d3e175"),
    "original_n8": ("history-96f-12888322275.zip", "cf356083e733c73ce68324444153a17269a66c555f31ed72df9ae98b36e95750"),
}
SOURCE = {
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs": "c89cb136534f5d67e8b5d5ec6df8893a44ac24ce",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs": "f9e91d9128b6ea196323772710a6a2929a7a65d6",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs": "cbd712a0f01b4fdab15cd4245eb95e39b22c9aea",
    "trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs": "4742ee2545d0120a543cc35da210e574f406e6c8",
    "trillionnium/crates/trnm-pon-node/tests/support/multiprocess_support.rs": "c20818e8cebdbf00b96599898456a88c63a18bd7",
}


def require(value, explanation):
    if not value:
        raise AssertionError(explanation)


def sha_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1 << 20):
            h.update(data)
    return h.hexdigest()


def read(archive, name):
    data = archive.read(name)
    return json.loads(data), hashlib.sha256(data).hexdigest()


def source_audit(source_dir):
    result, texts = [], {}
    for path, expected in SOURCE.items():
        data = (source_dir / path).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(blob == expected, "source Git blob differs: " + path)
        texts[path] = data.decode()
        result.append({"path": path, "git_blob": blob, "sha256": hashlib.sha256(data).hexdigest()})
    public = texts[next(p for p in SOURCE if p.endswith("/public_v3.rs"))]
    scalar = texts[next(p for p in SOURCE if p.endswith("/scalar_cpu.rs"))]
    constants = {}
    for name, text in [("CHALLENGES_PER_SECOND", public), ("CHALLENGE_BURST", public),
                       ("READ_CHALLENGE_RESERVE", public), ("MUTATION_CPU_BURST_NS", scalar),
                       ("MUTATION_CPU_REFILL_NS_PER_SECOND", scalar),
                       ("MUTATION_CPU_START_RESERVE_NS", scalar), ("MUTATION_CPU_WORKERS", scalar)]:
        found = re.search(r"const " + name + r": [^=]+ = ([0-9_]+);", text)
        require(found is not None, "source constant missing: " + name)
        constants[name] = int(found.group(1).replace("_", ""))
    return result, constants


def validate_flow(flow):
    require(flow["balance_identity_verified"], "flow reports unknown identity")
    require(flow["initial_credit_ns"] + flow["credited_refill_ns"]
            - flow["paid_cpu_debit_ns"] - flow["settlement_discard_ns"]
            == flow["remaining_paid_credit_ns"], "actual credit conservation")
    require(flow["remaining_paid_credit_ns"]
            == flow["stored_credit_ns"] + flow["booked_reservation_ns"], "reservation principal identity")
    require(flow["paid_cpu_debit_ns"]
            == flow["live_debited_cpu_ns"] + flow["settlement_residual_cpu_ns"], "paid CPU identity")
    require(flow["unsettled_known_live_cpu_ns"]
            == flow["paid_cpu_debit_ns"] - flow["settled_full_cpu_ns"], "settled CPU identity")


def original_predicate(meter, flow, clock_failures):
    return (flow["balance_identity_verified"]
            and flow["initial_credit_ns"] == meter["burst_ns"]
            and flow["remaining_paid_credit_ns"] < meter["start_reserve_ns"]
            and flow["paid_cpu_debit_ns"] > meter["burst_ns"] - meter["start_reserve_ns"]
            and clock_failures == 0 and not meter["accounting_unavailable"])


def digest_hex(value):
    return bytes(value).hex() if isinstance(value, list) else value


def inspect_phase(archive, round_number, mode, constants):
    member = f"n8/run-{round_number}-raw/{mode}.json"
    phase, member_sha = read(archive, member)
    require(phase["duration_seconds"] == 30, "original window")
    require(phase["public_resource_policy"]["policy_id"] == POLICY, "policy identity")
    require(phase["attacker_processes_ready"] == phase["attacker_processes_requested"] == 24,
            "all original attacker processes ready")
    require(phase["actor_reports_successful_without_cap_or_kill"], "actor completion")
    meter = phase["final_meter"]
    require(meter["burst_ns"] == constants["MUTATION_CPU_BURST_NS"]
            and meter["refill_ns_per_second"] == constants["MUTATION_CPU_REFILL_NS_PER_SECOND"]
            and meter["start_reserve_ns"] == constants["MUTATION_CPU_START_RESERVE_NS"]
            and meter["worker_limit"] == constants["MUTATION_CPU_WORKERS"], "actual receiver policy")
    flow = phase["final_actual_flow"]
    validate_flow(flow)
    require(flow["booked_reservation_ns"] == flow["live_owners"]
            == flow["unsettled_known_live_cpu_ns"] == 0, "final settlement")
    require(phase["initial_meter"]["stored_credit_ns"] == flow["initial_credit_ns"] == 2_000_000_000,
            "initial paid credit")
    observations = []
    for sample in phase["budget_samples"]:
        require("Ok" in sample["meter"], "budget sample available")
        observation = sample["meter"]["Ok"]
        current = observation["actual_flow"]
        require(current is not None, "actual flow available")
        validate_flow(current)
        depleted = original_predicate(observation["meter"], current, observation["clock_failures"])
        require(depleted == observation["depleted"], "unmodified predicate re-evaluation")
        require(not depleted, "unexpected depletion in same-host N8 sample")
        require(observation["clock_failures"] == 0 and not observation["meter"]["accounting_unavailable"],
                "known accounting")
        observations.append({"at_ns": sample["at_ns"], "flow": current})
    minimum = min(observations, key=lambda item: item["flow"]["remaining_paid_credit_ns"])
    require(phase["genuine_budget_depletion_observed"] is False and phase["depletion_at_ns"] is None,
            "recorded original depletion result")
    children = phase["children"]
    actors = [child["report"]["result"] for child in children]
    require(all(child["exit_success"] and not child["parent_forced_kill"] for child in children),
            "normal actor exits")
    require(not any(actor["attempt_cap_reached"] for actor in actors), "no attempt cap reached")
    calls = [call for actor in actors for call in actor["calls"]]
    attack_digests = {actor["acquisition"]["public_request_body_digest"] for actor in actors}
    require(all(actor["acquisition"]["relation_rejection_matches_mode"] for actor in actors),
            "original two rejection modes")
    records = phase["receiver_observation"]["records"]
    require(phase["receiver_observation"]["measurement_failures"] == 0
            and phase["receiver_observation"]["records_not_retained"] == 0, "complete receiver records")
    attack = [row for row in records if digest_hex(row["body_digest"]) in attack_digests]
    honest = [row for row in records if row["operation"] == 1
              and digest_hex(row["body_digest"]) not in attack_digests]
    attack_dispatched = [row for row in attack if row["dispatch_started"]]
    honest_dispatched = [row for row in honest if row["dispatch_started"]]
    require(len(honest_dispatched) == 21 and all(row["dispatch_accepted"] for row in honest_dispatched),
            "all 21 ordinary signed submissions accepted")
    require(all(not row["dispatch_accepted"] for row in attack_dispatched), "hostile dispatches rejected")
    hostile_cpu = sum(row["dispatch_thread_cpu_ns"] for row in attack_dispatched)
    honest_cpu = sum(row["dispatch_thread_cpu_ns"] for row in honest_dispatched)
    metrics = phase["service_outcome"]["Ok"]
    require(hostile_cpu + honest_cpu == flow["paid_cpu_debit_ns"] == metrics["mutation_cpu_charged_ns"],
            "independent raw dispatch partition equals exact paid ledger")
    require(metrics["mutation_cpu_clock_failures"] == metrics["mutation_cpu_refusals"] == 0,
            "no clock failures or paid credit refusals")
    successful_profiles = [call["metrics"] for call in calls if call["status"] == "refused"]
    profile_names = ["challenge_ns", "solution_search_ns", "solution_body_response_ns", "total_elapsed_ns"]
    profile = {name: statistics.mean(call[name] for call in successful_profiles) for name in profile_names}
    profile["challenge_share_of_mean_call_wall"] = profile["challenge_ns"] / profile["total_elapsed_ns"]
    phase_cpu, phase_wall = collections.Counter(), collections.Counter()
    for row in attack_dispatched:
        for item in row["submit_phases"]:
            if item["completed"]:
                phase_cpu[item["phase"]] += item["thread_cpu_ns"]
                phase_wall[item["phase"]] += item["wall_ns"]
    verifier = phase["history_verifier_process"]
    require(verifier["parent_before_spawn"]["cpu.max"] == "25000 100000", "separate verifier CPU cap")
    require(verifier["original_outer_cgroup"].startswith("/system.slice/")
            and verifier["ready"]["cgroup"].startswith("/trnmponpublic.slice/"), "separate cgroup domains")
    before = verifier["report"]["result"]["parent_before"]["cpu.stat"]
    after = verifier["report"]["result"]["parent_after_node_close"]["cpu.stat"]
    confirmations = [{k: row[k] for k in ["round", "started_ns", "ended_ns",
                     "confirmed_inside_pressure_window", "paid_credit_depletion_observed_during_round"]}
                     for row in phase["confirmations"]]
    threshold = (flow["initial_credit_ns"] + flow["credited_refill_ns"]
                 - flow["settlement_discard_ns"] - meter["start_reserve_ns"])
    return {
        "member": member, "member_sha256": member_sha, "round": round_number, "mode": mode,
        "initial_meter": phase["initial_meter"], "final_meter": meter, "final_actual_flow": flow,
        "sample_count": len(observations), "all_sample_balance_identities_recomputed": True,
        "all_sample_original_depletion_predicates_recomputed_false": True,
        "minimum_paid_credit_sample": minimum,
        "minimum_margin_above_start_reserve_ns": minimum["flow"]["remaining_paid_credit_ns"] - meter["start_reserve_ns"],
        "final_fixed_observed_refill_debit_threshold_ns": threshold,
        "final_fixed_observed_refill_debit_shortfall_ns": threshold - flow["paid_cpu_debit_ns"],
        "threshold_counterfactual_scope": "Algebra at the observed final refill/settlement; not a prediction under changed traffic, which can change refill discarded at a full bucket. Strict depletion requires debit greater than this threshold.",
        "business_started_ns": phase["business_started_ns"], "confirmations": confirmations,
        "attack_calls_overlapping_each_signed_round": phase["attack_calls_overlapping_each_signed_round"],
        "attack": {
            "actor_count": len(actors), "all_ready_normal_exit_no_cap_no_forced_kill": True,
            "call_count": len(calls), "call_status_counts": dict(collections.Counter(c["status"] for c in calls)),
            "first_call_started_ns": min(c["started_ns"] for c in calls),
            "last_call_started_ns": max(c["started_ns"] for c in calls),
            "records": len(attack), "dispatched": len(attack_dispatched),
            "dispatch_cpu_ns": hostile_cpu, "mean_dispatch_cpu_ns": hostile_cpu / len(attack_dispatched),
            "actor_traffic_cpu_ns_sum": sum(a["traffic_cpu_ns"] for a in actors),
            "refused_call_mean_profile_ns": profile,
            "nested_submit_phase_thread_cpu_ns_sum": dict(phase_cpu),
            "nested_submit_phase_wall_ns_sum": dict(phase_wall),
            "phase_cost_scope": "Nested in paid dispatch; cannot be added to it. Concurrent wall durations are not aggregate elapsed time.",
        },
        "honest": {"accepted_submit_count": len(honest_dispatched), "dispatch_cpu_ns": honest_cpu},
        "paid_dispatch_partition_equals_raw_ledger": True,
        "service": {k: metrics[k] for k in ["issued_challenges", "peak_pending_challenge",
             "pending_challenge_entered", "pending_challenge_granted", "pending_challenge_closed",
             "pending_challenge_wait_ns", "pending_grant_wait_ns", "queue_wait_ns", "peak_pending_enqueue",
             "mutation_cpu_reservations", "mutation_cpu_refusals", "mutation_cpu_clock_failures"]},
        "separate_verifier": {
            "outer_cgroup": verifier["original_outer_cgroup"], "verifier_cgroup": verifier["ready"]["cgroup"],
            "parent_cpu_max": verifier["parent_before_spawn"]["cpu.max"],
            "parent_cpu_stat_delta": {k: after[k] - before[k] for k in ["usage_usec", "nr_periods", "nr_throttled", "throttled_usec"]},
            "whole_verifier_process_cpu_ns": verifier["report"]["result"]["whole_verifier_process_cpu_ns"],
            "whole_verifier_wall_ns": verifier["report"]["result"]["whole_verifier_wall_ns"],
            "paid_receiver_ledger_includes_verifier_cpu": False,
        },
        "whole_parent_phase_cpu_ns": phase["whole_parent_phase_cpu_ns"],
        "whole_parent_phase_wall_ns": phase["whole_parent_phase_wall_ns"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, default=ROOT,
                        help="Directory containing both original artifact ZIPs; no extraction required.")
    parser.add_argument("--source-dir", type=Path, default=ROOT.parent / "repo",
                        help="Repository containing the five pinned c571/96f runtime/test source files.")
    parser.add_argument("--output", type=Path, default=ROOT / "history-96f-same-host-n8-paid-credit-diagnosis.json")
    args = parser.parse_args()
    sources, constants = source_audit(args.source_dir)
    archive_binding = {}
    for label, (filename, expected) in ARCHIVES.items():
        path = args.artifacts_dir / filename
        actual = sha_file(path)
        require(actual == expected, "original archive SHA256: " + label)
        archive_binding[label] = {"filename": filename, "sha256": actual, "bytes": path.stat().st_size}
    with zipfile.ZipFile(args.artifacts_dir / ARCHIVES["paired"][0]) as archive:
        source_before, _ = read(archive, "n8/source-before.json")
        source_after, _ = read(archive, "n8/source-after.json")
        require(source_before == source_after and source_before["tested_commit"] == HEAD
                and source_before["tested_tree"] == TREE and source_before["tracked_worktree_verified"],
                "paired exact source before/after")
        resource, _ = read(archive, "n8/resource-before-build.json")
        outer = next(item for item in resource["limits"] if item["path"].endswith(resource["cgroup"]))
        require(outer["cpu.max"] == "400000 100000", "receiver outer cgroup has four CPUs, not 25%")
        phases = [inspect_phase(archive, number, mode, constants)
                  for number in range(1, 4) for mode in ["from-zero", "late-product"]]
    counterexamples = []
    with zipfile.ZipFile(args.artifacts_dir / ARCHIVES["original_n8"][0]) as archive:
        before, _ = read(archive, "source-before.json")
        require(before["tested_commit"] == HEAD and before["tested_tree"] == TREE,
                "counterexample same source head")
        for number in range(1, 4):
            for mode in ["from-zero", "late-product"]:
                name = f"run-{number}-raw/{mode}.json"
                phase, member_sha = read(archive, name)
                require(phase["public_resource_policy"]["policy_id"] == POLICY, "counterexample same policy")
                qualifying = []
                for sample in phase["budget_samples"]:
                    observation = sample["meter"].get("Ok")
                    if observation and observation["actual_flow"]:
                        validate_flow(observation["actual_flow"])
                        if original_predicate(observation["meter"], observation["actual_flow"], observation["clock_failures"]):
                            qualifying.append(observation)
                require(phase["genuine_budget_depletion_observed"] and qualifying,
                        "actual same-policy depletion counterexample")
                counterexamples.append({"member": name, "member_sha256": member_sha,
                    "first_qualifying_original_sample": qualifying[0],
                    "verifier_binary_sha256": phase["history_verifier_process"]["binary_sha256"],
                    "boot_id": phase["history_verifier_process"]["parent_before_spawn"]["boot_id"]})
    output = {
        "schema": "history-96f-same-host-n8-paid-credit-diagnosis-v1", "head": HEAD, "tree": TREE,
        "paired_run_url": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40852779415",
        "original_counterexample_run_url": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40852779337",
        "archives": archive_binding, "pinned_source_files": sources, "source_policy_constants": constants,
        "public_resource_policy_id": POLICY, "paired_outer_cpu_max": outer["cpu.max"],
        "nominal_30_second_challenge_budget_reference": constants["CHALLENGE_BURST"] + 30 * constants["CHALLENGES_PER_SECOND"],
        "challenge_budget_reference_scope": "A nominal full-burst 30-second reference, not an assertion that all recorded challenges were issued exactly inside the attack epoch. Eight tokens are reserved from mutating requests, read requests share the same budget, and phase shutdown/last reads can extend beyond 30 seconds.",
        "hostile_only_refill_break_even_at_128_per_second_ns": constants["MUTATION_CPU_REFILL_NS_PER_SECOND"] / constants["CHALLENGES_PER_SECOND"],
        "phases": phases, "same_policy_original_n8_depletion_counterexamples": counterexamples,
        "diagnosis": {
            "depletion_false_because": "Actual paid remaining credit stays above 100,000,000 ns in every retained sample; all six final debit partitions and all retained sample identities reconcile. Gross paid debit greater than 1.9 seconds alone is insufficient after credited refill.",
            "mathematical_impossibility_from_25_percent_cap": False,
            "cap_domain_reason": "The 25% cgroup is the separate History verifier. The receiving parent is in the original 400% outer cgroup and its two paid mutation workers use a refillable scalar budget. Verifier CPU does not debit that budget.",
            "observed_attack_flow": "All 24 actors continuously offer calls until the original 30-second end without a call cap. Shared challenge issuance is near 128/s; around 94% of mean refused-call wall time is awaiting challenge. Measured rejected dispatch CPU is 1.57-1.95 ms, insufficient here to exhaust initial credit while the bucket refills at 0.25 CPU seconds/s and honest requests also debit it.",
            "business_confirmation": "All 21 signed submissions are accepted; first two confirmations are inside the pressure window and the third is late in each attack phase. Separate verifier cgroup throttling is observed; this late confirmation failure and paid-credit depletion are distinct predicates.",
            "unnecessary_sync_or_duplicate_work_proven": False,
            "optimization_conclusion": "No change proposed. Context-owner wait instrumentation and current profiles do not prove removable synchronization or redundant validation. The measured challenge wait is the explicit existing ingress policy, not a demonstrated implementation defect.",
        },
        "limits": ["Read-only analysis of existing raw observations; no new native execution.",
            "A 50 ms retained sampler does not prove the absence of an unsampled transient low credit.",
            "No universal upper bound on paid request cost was proven; no policy-wide impossibility follows from this six-phase cost sample.",
            "Counterexamples have different host/binary from the paired run; they only disprove same-policy impossibility, not establish a causal hardware speedup.",
            "No flamegraph, stack profile, lock profiler, energy measurement, or optimization experiment was performed.",
            "All original gates, budgets, attack modes and failures remain unchanged."],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"audit": "PASS", "output": str(args.output), "sha256": sha_file(args.output),
                      "paired_attack_phases": len(phases), "balance_samples": sum(p["sample_count"] for p in phases),
                      "depletion_counterexamples": len(counterexamples)}, sort_keys=True))


if __name__ == "__main__":
    main()
