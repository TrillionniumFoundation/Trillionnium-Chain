#!/usr/bin/env python3
import argparse
import glob
import os
import re
import statistics
from datetime import datetime

KV = re.compile(r"([a-zA-Z0-9_\.]+)=([^\s]+)")


def latest(pattern: str):
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def parse_kv_line(line: str):
    return {k: v for k, v in KV.findall(line)}


def load_kv_rows(path: str | None):
    rows = []
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                parsed = parse_kv_line(raw.strip())
                if parsed:
                    rows.append(parsed)
    return rows


def as_num(v):
    try:
        return int(v)
    except Exception:
        try:
            return float(v)
        except Exception:
            return v


def summarize(vals):
    vals = [as_num(v) for v in vals]
    if not vals:
        return None
    vals = sorted(vals)
    p95 = vals[min(len(vals) - 1, int(len(vals) * 0.95))]
    return vals[0], statistics.median(vals), p95, vals[-1]


def fmt_metric(name: str, vals):
    s = summarize(vals)
    if not s:
        return f"- {name}: n/a"
    mn, p50, p95, mx = s
    return f"- {name}: min={mn} p50={p50} p95={p95} max={mx}"


def recommended_producer(label: str) -> str:
    if label == "node_log":
        return (
            "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 "
            "--max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log"
        )
    if label == "classic_bench":
        return "./scripts/run_bench_matrix.sh"
    if label == "mixed_bench":
        return "./scripts/run_bench_mixed_matrix.sh"
    if label == "executor_profile":
        return "python3 scripts/executor_profile_report.py"
    return "unknown"


def autopilot_severity(missing_inputs, stale_inputs, old_inputs) -> str:
    if not missing_inputs and not stale_inputs and not old_inputs:
        return "GREEN"
    if missing_inputs:
        if len(missing_inputs) >= 3:
            return "RED"
        return "YELLOW"
    if old_inputs:
        return "YELLOW"
    return "GREEN"


def main():
    p = argparse.ArgumentParser(description="Render profiling closeout baseline from node/bench outputs")
    p.add_argument("--node-log", default=None)
    p.add_argument("--classic", default=None)
    p.add_argument("--mixed", default=None)
    p.add_argument("--executor-profile", default=None)
    p.add_argument("--out", default=None)
    args = p.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    node_log = args.node_log or latest(os.path.join(root, "run", "parallel-sanity.log"))
    classic = args.classic or latest(os.path.join(root, "run", "bench", "bench-matrix-*.txt"))
    mixed = args.mixed or latest(os.path.join(root, "run", "bench", "bench-mixed-matrix-*.txt"))
    executor_profile = args.executor_profile or latest(os.path.join(root, "run", "bench", "executor-profile-summary-*.txt"))
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or os.path.join(root, "docs", "reports", f"profiling-closeout-baseline-{ts}.md")

    block_rows = []
    consensus_rows = []
    classic_rows = load_kv_rows(classic)
    mixed_rows = load_kv_rows(mixed)
    if node_log and os.path.exists(node_log):
        with open(node_log, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("[block] "):
                    block_rows.append(parse_kv_line(line))
                elif line.startswith("[consensus] "):
                    consensus_rows.append(parse_kv_line(line))

    def input_status(path: str | None) -> str:
        if not path:
            return "missing"
        return "present" if os.path.exists(path) else "missing"

    def file_age_seconds(path: str | None):
        if not path or not os.path.exists(path):
            return None
        return max(0, int((datetime.now() - datetime.fromtimestamp(os.path.getmtime(path))).total_seconds()))

    def freshness_label(age_seconds: int | None) -> str:
        if age_seconds is None:
            return "missing"
        if age_seconds <= 15 * 60:
            return "fresh"
        if age_seconds <= 2 * 60 * 60:
            return "stale"
        return "old"

    lines = ["# Profiling Closeout Baseline", f"generated_at={datetime.now().isoformat()}", "", "## Inputs"]
    lines += [
        f"- node_log: {node_log}",
        f"- node_log_status: {input_status(node_log)}",
        f"- classic_bench: {classic}",
        f"- classic_bench_status: {input_status(classic)}",
        f"- mixed_bench: {mixed}",
        f"- mixed_bench_status: {input_status(mixed)}",
        f"- executor_profile: {executor_profile}",
        f"- executor_profile_status: {input_status(executor_profile)}",
        "",
        "## Input Freshness",
    ]

    freshness_rows = [
        ("node_log", node_log),
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    stale_inputs = []
    old_inputs = []
    for label, path in freshness_rows:
        age_seconds = file_age_seconds(path)
        freshness = freshness_label(age_seconds)
        if freshness == "stale":
            stale_inputs.append(label)
        elif freshness == "old":
            old_inputs.append(label)
        lines.append(
            f"- {label}: freshness={freshness} age_seconds={age_seconds if age_seconds is not None else 'n/a'}"
        )

    lines += ["", "## Input Readiness"]

    readiness_rows = [
        ("node_log", input_status(node_log), recommended_producer("node_log")),
        ("classic_bench", input_status(classic), recommended_producer("classic_bench")),
        ("mixed_bench", input_status(mixed), recommended_producer("mixed_bench")),
        (
            "executor_profile",
            input_status(executor_profile),
            recommended_producer("executor_profile"),
        ),
    ]
    for label, status, producer in readiness_rows:
        lines.append(f"- {label}: {status} | producer={producer}")

    lines += ["", "## Data Completeness"]

    inputs = [
        ("node_log", node_log),
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    present_count = sum(1 for _, path in inputs if path and os.path.exists(path))

    if present_count == 0:
        lines.append("- autopilot_assessment: BENCH_ONLY_RUN (must-run gate passed, but no persisted closeout artifacts were found)")
        lines.append("- note: `cargo run -q -p trnm-bench -- --profile` prints useful immediate telemetry, but closeout files must be produced separately for curator/autopilot consumption")
    elif present_count < len(inputs):
        lines.append("- autopilot_assessment: PARTIAL_CLOSEOUT (some persisted closeout artifacts are present, but the evidence set is incomplete)")
        lines.append("- note: closeout is usable for directional review, but curator/autopilot decisions should prefer a full 4/4 evidence set")
    else:
        lines.append("- autopilot_assessment: COMPLETE_CLOSEOUT (all persisted closeout artifacts are present)")

    missing_inputs = []
    present_inputs = []
    for label, path in inputs:
        if not path or not os.path.exists(path):
            missing_inputs.append(label)
        else:
            present_inputs.append(label)

    if missing_inputs:
        lines.append(f"- status: PARTIAL ({', '.join(missing_inputs)} missing)")
    else:
        lines.append("- status: COMPLETE")
    lines.append(f"- present_inputs: {', '.join(present_inputs) if present_inputs else 'none'}")
    lines.append(f"- missing_inputs: {', '.join(missing_inputs) if missing_inputs else 'none'}")
    lines.append(f"- stale_inputs: {', '.join(stale_inputs) if stale_inputs else 'none'}")
    lines.append(f"- old_inputs: {', '.join(old_inputs) if old_inputs else 'none'}")
    lines.append(f"- readiness_score: {len(present_inputs)}/{len(inputs)}")
    lines.append(
        f"- autopilot_severity: {autopilot_severity(missing_inputs, stale_inputs, old_inputs)}"
    )

    lines += ["", "## Autopilot Recommended Next Steps"]
    if missing_inputs:
        for label, status, producer in readiness_rows:
            if status != "present":
                lines.append(f"- produce {label}: {producer}")
    if stale_inputs:
        for label in stale_inputs:
            lines.append(f"- refresh {label}: existing artifact is stale; regenerate before curator/autopilot review")
    if old_inputs:
        for label in old_inputs:
            lines.append(f"- refresh {label}: existing artifact is old; do not treat as current evidence")
    if not missing_inputs and not stale_inputs and not old_inputs:
        lines.append("- none: all expected closeout inputs are present and fresh")

    lines += ["", "## Block Metrics"]
    for key in [
        "scheduler_elapsed_ms",
        "preexec_elapsed_ms",
        "commit_elapsed_ms",
        "state_root_total_ms",
        "critical_wait_blocks",
        "rollback_count",
        "groups",
        "elapsed_ms",
    ]:
        lines.append(fmt_metric(key, [r.get(key) for r in block_rows if key in r]))

    lines += ["", "## Consensus Summary"]
    if consensus_rows:
        c = consensus_rows[-1]
        for key in [
            "finality_p50_ms",
            "finality_p95_ms",
            "scheduler_elapsed_p50_ms",
            "scheduler_elapsed_p95_ms",
            "preexec_elapsed_p50_ms",
            "preexec_elapsed_p95_ms",
            "commit_elapsed_p50_ms",
            "commit_elapsed_p95_ms",
            "state_root_total_p50_ms",
            "state_root_total_p95_ms",
            "critical_wait_blocks_p50",
            "critical_wait_blocks_p95",
            "rollback_total",
            "preexec_reject_total",
            "apply_error_total",
            "bft_round_change_total",
        ]:
            if key in c:
                lines.append(f"- {key}: {c[key]}")
    else:
        lines.append("- consensus summary: missing")

    lines += ["", "## Benchmark Summary"]
    lines.append(
        f"- benchmark_artifact_coverage: {len([p for p in [classic, mixed, executor_profile] if p and os.path.exists(p)])}/3"
    )
    bench_metric_labels = [
        ("classic", classic_rows),
        ("mixed", mixed_rows),
    ]
    bench_metric_keys = [
        "elapsed_ms",
        "groups",
        "grouped",
        "estimated_conflict_rate",
        "profile.report.coverage_ratio",
        "profile.report.groups_per_1k_txs",
        "profile.report.grouping_efficiency",
        "profile.conflict_hit_rate",
        "profile.hot_object_share",
    ]
    for label, rows in bench_metric_labels:
        if rows:
            lines.append(f"- {label}_bench_rows: {len(rows)}")
            latest_row = rows[-1]
            for key in bench_metric_keys:
                if key in latest_row:
                    lines.append(f"- {label}_bench.{key}: {latest_row[key]}")
        else:
            lines.append(f"- {label}_bench_rows: 0")
    if classic and os.path.exists(classic):
        lines.append(
            f"- classic_bench_freshness: {freshness_label(file_age_seconds(classic))}"
        )
    else:
        lines.append("- classic_bench_freshness: missing")
    if mixed and os.path.exists(mixed):
        lines.append(
            f"- mixed_bench_freshness: {freshness_label(file_age_seconds(mixed))}"
        )
    else:
        lines.append("- mixed_bench_freshness: missing")
    if executor_profile and os.path.exists(executor_profile):
        lines.append(
            f"- executor_profile_freshness: {freshness_label(file_age_seconds(executor_profile))}"
        )
        with open(executor_profile, "r", encoding="utf-8") as f:
            lines.extend([line.rstrip() for line in f])
    else:
        lines.append("- executor_profile_freshness: missing")
        lines.append("- executor profile summary: missing")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] profiling closeout baseline: {out}")


if __name__ == "__main__":
    main()
