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
        "## Input Readiness",
    ]

    readiness_rows = [
        (
            "node_log",
            input_status(node_log),
            "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log",
        ),
        (
            "classic_bench",
            input_status(classic),
            "TXS=1000 ./scripts/run_bench_matrix.sh",
        ),
        (
            "mixed_bench",
            input_status(mixed),
            "TXS=1000 ./scripts/run_bench_mixed_matrix.sh",
        ),
        (
            "executor_profile",
            input_status(executor_profile),
            "python3 scripts/executor_profile_report.py",
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
    lines.append(f"- readiness_score: {len(present_inputs)}/{len(inputs)}")

    lines += ["", "## Autopilot Recommended Next Steps"]
    if missing_inputs:
        for label, status, producer in readiness_rows:
            if status != "present":
                lines.append(f"- produce {label}: {producer}")
    else:
        lines.append("- none: all expected closeout inputs are present")

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
    if executor_profile and os.path.exists(executor_profile):
        with open(executor_profile, "r", encoding="utf-8") as f:
            lines.extend([line.rstrip() for line in f])
    else:
        lines.append("- executor profile summary: missing")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] profiling closeout baseline: {out}")


if __name__ == "__main__":
    main()
