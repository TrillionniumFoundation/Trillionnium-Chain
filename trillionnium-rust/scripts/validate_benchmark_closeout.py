#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$")
HEX40_RE = re.compile(r"^[a-f0-9]{40}$")
WORKLOADS = ["classic", "mixed", "hot-streak"]
SEGMENT_ORDER = [
    "client_submit",
    "mempool_queue",
    "consensus",
    "scheduler_grouping",
    "execution",
    "commit",
    "storage",
    "finality_observation",
]
REQUIRED_E2E_FIELDS = [
    "submit_tps",
    "finalized_tps",
    "finality_p50_ms",
    "finality_p95_ms",
    "finality_p99_ms",
    "drop_rate",
    "retry_rate",
    "rollback_rate",
    "scheduler_window_share",
    "bottleneck_segment",
]


def fail(msg):
    print(f"VALIDATION_ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def expect(cond, msg):
    if not cond:
        fail(msg)


def expect_keys(obj, keys, label):
    missing = [k for k in keys if k not in obj]
    expect(not missing, f"{label} missing keys: {missing}")


def expect_utc_or_null(v, label):
    if v is None:
        return
    expect(isinstance(v, str) and UTC_RE.match(v), f"{label} must be UTC timestamp or null")


def expect_num_or_null(v, label):
    expect(v is None or isinstance(v, (int, float)), f"{label} must be number or null")


def main():
    ap = argparse.ArgumentParser(description="Validate TRNM benchmark closeout + E2E bridge artifact")
    ap.add_argument("json_path", help="path to benchmark-closeout.json")
    args = ap.parse_args()

    p = Path(args.json_path)
    expect(p.exists(), f"artifact not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))

    expect_keys(data, [
        "generated_at", "inputs", "git", "hardware", "benchmark_profile",
        "summary", "e2e_mapping_template", "e2e_bridge"
    ], "root")
    expect(isinstance(data["generated_at"], str) and UTC_RE.match(data["generated_at"]), "generated_at must be UTC timestamp")

    expect_keys(data["inputs"], ["regression_csv"], "inputs")
    expect(isinstance(data["inputs"]["regression_csv"], str) and data["inputs"]["regression_csv"], "inputs.regression_csv must be non-empty string")

    expect_keys(data["git"], ["branch", "head"], "git")
    if data["git"]["branch"] is not None:
        expect(isinstance(data["git"]["branch"], str), "git.branch must be string or null")
    if data["git"]["head"] is not None:
        expect(isinstance(data["git"]["head"], str) and HEX40_RE.match(data["git"]["head"]), "git.head must be 40-char lowercase hex or null")

    profile = data["benchmark_profile"]
    expect_keys(profile, ["profile_id", "measurement_window", "warmup_policy", "target_tps_windows", "workload_family", "disclaimer"], "benchmark_profile")
    expect(sorted(profile["workload_family"]) == sorted(WORKLOADS), "benchmark_profile.workload_family must contain classic/mixed/hot-streak")
    expect(all(isinstance(x, int) and x > 0 for x in profile["target_tps_windows"]), "target_tps_windows must be positive integers")
    target_keys = {str(x) for x in profile["target_tps_windows"]}

    summary = data["summary"]
    expect_keys(summary, ["row_count", "strategy_sources", "workloads"], "summary")
    expect(isinstance(summary["row_count"], int) and summary["row_count"] >= 0, "summary.row_count must be non-negative int")
    expect(sorted(summary["workloads"].keys()) == sorted(WORKLOADS), "summary.workloads must contain all three workload families")

    mapping = data["e2e_mapping_template"]
    expect(mapping.get("required_fields") == REQUIRED_E2E_FIELDS, "e2e_mapping_template.required_fields drifted")
    expect(mapping.get("segment_order") == SEGMENT_ORDER, "e2e_mapping_template.segment_order drifted")

    bridge = data["e2e_bridge"]
    expect_keys(bridge, ["schema_version", "status", "placeholder_policy", "system_timestamps", "workloads"], "e2e_bridge")
    expect(bridge["schema_version"] == "trnm.benchmark-closeout.e2e-bridge.v1", "unexpected e2e_bridge.schema_version")
    expect(bridge["status"] in {"placeholder_only", "partial", "complete"}, "invalid e2e_bridge.status")
    expect(bridge["placeholder_policy"] == "null means not yet measured; placeholders must not be interpreted as observed data", "unexpected placeholder_policy")
    expect(sorted(bridge["workloads"].keys()) == sorted(WORKLOADS), "e2e_bridge.workloads must contain all three workload families")

    expect_keys(bridge["system_timestamps"], [
        "run_started_at_utc", "submit_window_started_at_utc", "submit_window_ended_at_utc", "finality_observed_at_utc"
    ], "e2e_bridge.system_timestamps")
    for k, v in bridge["system_timestamps"].items():
        expect_utc_or_null(v, f"e2e_bridge.system_timestamps.{k}")

    for wl in WORKLOADS:
        wl_summary = summary["workloads"][wl]
        expect_keys(wl_summary, [
            "rows", "original_rows", "aggressive_rows", "elapsed_ms", "groups",
            "micro_scheduler_ceiling_tps", "groups_per_ktx", "elapsed_ms_per_ktx",
            "aggressive_minus_original_ms", "bridge_to_system", "cases", "pairwise_deltas"
        ], f"summary.workloads.{wl}")
        ref_share = wl_summary["bridge_to_system"]["window_share_avg_original"]
        expect(set(ref_share.keys()) == target_keys, f"summary.workloads.{wl}.bridge_to_system.window_share_avg_original keys must match target_tps_windows")

        wl_bridge = bridge["workloads"][wl]
        expect_keys(wl_bridge, [
            "measurement_status", "timestamps", "metrics", "segment_latency_ms",
            "scheduler_window_share_reference", "bottleneck_segment"
        ], f"e2e_bridge.workloads.{wl}")
        expect(wl_bridge["measurement_status"] in {"placeholder_only", "partial", "complete"}, f"invalid measurement_status for {wl}")
        expect(wl_bridge["scheduler_window_share_reference"] == ref_share, f"scheduler_window_share_reference mismatch for {wl}")
        expect(set(wl_bridge["segment_latency_ms"].keys()) == set(SEGMENT_ORDER), f"segment_latency_ms keys mismatch for {wl}")
        for seg, v in wl_bridge["segment_latency_ms"].items():
            expect_num_or_null(v, f"e2e_bridge.workloads.{wl}.segment_latency_ms.{seg}")
        expect(wl_bridge["bottleneck_segment"] in set(SEGMENT_ORDER) | {None, "undetermined"}, f"invalid bottleneck_segment for {wl}")

        expect_keys(wl_bridge["timestamps"], [
            "submit_first_seen_at_utc", "submit_last_seen_at_utc", "first_finalized_at_utc", "last_finalized_at_utc"
        ], f"e2e_bridge.workloads.{wl}.timestamps")
        for k, v in wl_bridge["timestamps"].items():
            expect_utc_or_null(v, f"e2e_bridge.workloads.{wl}.timestamps.{k}")

        expect_keys(wl_bridge["metrics"], [
            "submit_tps", "finalized_tps", "finality_p50_ms", "finality_p95_ms",
            "finality_p99_ms", "drop_rate", "retry_rate", "rollback_rate"
        ], f"e2e_bridge.workloads.{wl}.metrics")
        for k, v in wl_bridge["metrics"].items():
            expect_num_or_null(v, f"e2e_bridge.workloads.{wl}.metrics.{k}")

        if wl_bridge["measurement_status"] == "placeholder_only":
            expect(all(v is None for v in wl_bridge["timestamps"].values()), f"placeholder workload {wl} must keep timestamps null")
            expect(all(v is None for v in wl_bridge["metrics"].values()), f"placeholder workload {wl} must keep metrics null")
            expect(all(v is None for v in wl_bridge["segment_latency_ms"].values()), f"placeholder workload {wl} must keep segment latencies null")
            expect(wl_bridge["bottleneck_segment"] == "undetermined", f"placeholder workload {wl} must keep bottleneck_segment undetermined")

    if bridge["status"] == "placeholder_only":
        expect(all(v is None for v in bridge["system_timestamps"].values()), "placeholder bridge must keep system_timestamps null")
        expect(all(w["measurement_status"] == "placeholder_only" for w in bridge["workloads"].values()), "placeholder bridge requires all workloads placeholder_only")

    print(f"VALIDATION_OK: {p}")


if __name__ == "__main__":
    main()
