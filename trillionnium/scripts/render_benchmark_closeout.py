#!/usr/bin/env python3
import argparse
import csv
import glob
import json
import os
import platform
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT / "run" / "bench"
DEFAULT_TARGET_TPS = [1000, 5000, 10000]
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


def latest(pattern: str):
    xs = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return xs[0] if xs else None


def try_int(v, default=0):
    try:
        return int(float(v))
    except Exception:
        return default


def try_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def git_head(root: Path):
    return run(["git", "-C", str(root.parent), "rev-parse", "HEAD"])


def git_branch(root: Path):
    return run(["git", "-C", str(root.parent), "branch", "--show-current"])


def detect_hardware():
    hw = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
    }
    sysctl_keys = {
        "cpu_brand": "machdep.cpu.brand_string",
        "cpu_cores_logical": "hw.logicalcpu",
        "cpu_cores_physical": "hw.physicalcpu",
        "mem_bytes": "hw.memsize",
    }
    for k, key in sysctl_keys.items():
        v = run(["sysctl", "-n", key])
        if v:
            hw[k] = v
    return hw


def summarize_nums(nums):
    if not nums:
        return {"min": None, "max": None, "avg": None}
    return {"min": min(nums), "max": max(nums), "avg": round(mean(nums), 4)}


def scheduler_ceiling_tps(txs: int, elapsed_ms: int):
    if txs <= 0 or elapsed_ms <= 0:
        return None
    return round(txs * 1000.0 / elapsed_ms, 2)


def scheduler_window_share(elapsed_ms: int, txs: int, target_tps: int):
    if elapsed_ms <= 0 or txs <= 0 or target_tps <= 0:
        return None
    required_window_ms = txs * 1000.0 / target_tps
    if required_window_ms <= 0:
        return None
    return round(elapsed_ms / required_window_ms, 6)


def load_rows(csv_path: Path):
    with open(csv_path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_summary(rows, targets_tps):
    by_workload = defaultdict(list)
    by_case = defaultdict(dict)
    strategy_sources = set()

    for r in rows:
        wl = r.get("workload", "unknown")
        strategy = r.get("strategy", "unknown")
        txs = try_int(r.get("txs"))
        keys = try_int(r.get("keys"))
        elapsed = try_int(r.get("elapsed_ms"))
        groups = try_int(r.get("groups"))
        strategy_sources.add((r.get("strategy_source") or "unknown").strip())
        enriched = dict(r)
        enriched["txs"] = txs
        enriched["keys"] = keys
        enriched["elapsed_ms"] = elapsed
        enriched["groups"] = groups
        enriched["micro_scheduler_ceiling_tps"] = scheduler_ceiling_tps(txs, elapsed)
        enriched["groups_per_ktx"] = round(groups * 1000.0 / txs, 4) if txs > 0 else None
        enriched["elapsed_ms_per_ktx"] = round(elapsed * 1000.0 / txs, 4) if txs > 0 else None
        enriched["scheduler_window_share"] = {
            str(t): scheduler_window_share(elapsed, txs, t) for t in targets_tps
        }
        by_workload[wl].append(enriched)
        by_case[(wl, txs, keys)][strategy] = enriched

    workloads = {}
    for wl, items in sorted(by_workload.items()):
        orig = [x for x in items if x.get("strategy") == "original"]
        aggr = [x for x in items if x.get("strategy") == "aggressive-greedy"]
        deltas = []
        for (c_wl, txs, keys), pair in sorted(by_case.items()):
            if c_wl != wl or "original" not in pair or "aggressive-greedy" not in pair:
                continue
            d = pair["aggressive-greedy"]["elapsed_ms"] - pair["original"]["elapsed_ms"]
            deltas.append({
                "txs": txs,
                "keys": keys,
                "delta_ms": d,
                "original_elapsed_ms": pair["original"]["elapsed_ms"],
                "aggressive_elapsed_ms": pair["aggressive-greedy"]["elapsed_ms"],
            })

        workloads[wl] = {
            "rows": len(items),
            "original_rows": len(orig),
            "aggressive_rows": len(aggr),
            "elapsed_ms": summarize_nums([x["elapsed_ms"] for x in orig]),
            "groups": summarize_nums([x["groups"] for x in orig]),
            "micro_scheduler_ceiling_tps": summarize_nums([
                x["micro_scheduler_ceiling_tps"] for x in orig if x["micro_scheduler_ceiling_tps"] is not None
            ]),
            "groups_per_ktx": summarize_nums([
                x["groups_per_ktx"] for x in orig if x["groups_per_ktx"] is not None
            ]),
            "elapsed_ms_per_ktx": summarize_nums([
                x["elapsed_ms_per_ktx"] for x in orig if x["elapsed_ms_per_ktx"] is not None
            ]),
            "aggressive_minus_original_ms": summarize_nums([d["delta_ms"] for d in deltas]),
            "bridge_to_system": {
                "interpretation": [
                    "micro_scheduler_ceiling_tps is an execution-kernel upper bound, not chain TPS",
                    "scheduler_window_share[target_tps] estimates how much of a target throughput window is spent inside scheduler grouping alone",
                    "remaining system budget must still cover ingress, mempooling, consensus, execution, commit, storage, and finality"
                ],
                "window_share_avg_original": {
                    str(t): round(mean([
                        x["scheduler_window_share"][str(t)] for x in orig if x["scheduler_window_share"][str(t)] is not None
                    ]), 6) if orig else None
                    for t in targets_tps
                },
            },
            "cases": sorted(orig, key=lambda x: (x["txs"], x["keys"])),
            "pairwise_deltas": deltas,
        }

    return {
        "row_count": len(rows),
        "strategy_sources": sorted(x for x in strategy_sources if x),
        "workloads": workloads,
    }


def build_e2e_bridge(summary, segment_order):
    workloads = {}
    for wl, data in summary["workloads"].items():
        workloads[wl] = {
            "measurement_status": "placeholder_only",
            "timestamps": {
                "submit_first_seen_at_utc": None,
                "submit_last_seen_at_utc": None,
                "first_finalized_at_utc": None,
                "last_finalized_at_utc": None,
            },
            "metrics": {
                "submit_tps": None,
                "finalized_tps": None,
                "finality_p50_ms": None,
                "finality_p95_ms": None,
                "finality_p99_ms": None,
                "drop_rate": None,
                "retry_rate": None,
                "rollback_rate": None,
            },
            "segment_latency_ms": {segment: None for segment in segment_order},
            "scheduler_window_share_reference": data["bridge_to_system"]["window_share_avg_original"],
            "bottleneck_segment": "undetermined",
        }

    return {
        "schema_version": "trnm.benchmark-closeout.e2e-bridge.v1",
        "status": "placeholder_only",
        "placeholder_policy": "null means not yet measured; placeholders must not be interpreted as observed data",
        "system_timestamps": {
            "run_started_at_utc": None,
            "submit_window_started_at_utc": None,
            "submit_window_ended_at_utc": None,
            "finality_observed_at_utc": None,
        },
        "workloads": workloads,
    }


def render_md(payload, out_json: Path):
    src = payload["inputs"]["regression_csv"]
    lines = [
        "# TRNM Benchmark Closeout Snapshot",
        "",
        f"- generated_at: `{payload['generated_at']}`",
        f"- source_csv: `{src}`",
        f"- git_branch: `{payload['git']['branch'] or 'unknown'}`",
        f"- git_head: `{payload['git']['head'] or 'unknown'}`",
        f"- closeout_json: `{out_json}`",
        "",
        "## 1. Scope & guardrails",
        "- This artifact normalizes current classic / mixed / hot-streak micro-bench evidence.",
        "- `micro_scheduler_ceiling_tps` is only a scheduler/executor-kernel upper bound; it is **not** chain-level TPS.",
        "- Bridge fields convert micro results into system-budget language so E2E lanes can add ingress / mempool / consensus / commit / storage / finality timings on top.",
        "",
        "## 2. Hardware / window / profile",
        f"- benchmark_profile_id: `{payload['benchmark_profile']['profile_id']}`",
        f"- measurement_window: `{payload['benchmark_profile']['measurement_window']}`",
        f"- warmup_policy: `{payload['benchmark_profile']['warmup_policy']}`",
        f"- strategy_source: `{','.join(payload['summary']['strategy_sources']) or 'unknown'}`",
        f"- target_tps_windows: `{', '.join(map(str, payload['benchmark_profile']['target_tps_windows']))}`",
        f"- hardware: `{json.dumps(payload['hardware'], ensure_ascii=False)}`",
        "",
        "## 3. Workload summary",
        "",
        "| workload | original rows | elapsed_ms(min/avg/max) | groups(min/avg/max) | scheduler ceiling TPS avg | aggressive-original delta ms (min/avg/max) |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for wl, data in payload["summary"]["workloads"].items():
        e = data["elapsed_ms"]
        g = data["groups"]
        c = data["micro_scheduler_ceiling_tps"]
        d = data["aggressive_minus_original_ms"]
        lines.append(
            f"| {wl} | {data['original_rows']} | {e['min']}/{e['avg']}/{e['max']} | {g['min']}/{g['avg']}/{g['max']} | {c['avg']} | {d['min']}/{d['avg']}/{d['max']} |"
        )

    lines += [
        "",
        "## 4. Bridge to system metrics",
        "- For each workload we compute `scheduler_window_share[target_tps]`.",
        "- Example: share=0.18 at 5000 TPS means scheduler grouping alone would consume ~18% of the 1-second throughput budget for that load shape.",
        "- Remaining budget must absorb: client submit, mempool queueing, consensus rounds, execution, commit, storage/fsync, and finality observation.",
        "",
    ]

    for wl, data in payload["summary"]["workloads"].items():
        lines.append(f"### {wl}")
        for target, share in data["bridge_to_system"]["window_share_avg_original"].items():
            lines.append(f"- avg scheduler_window_share @ {target} TPS: `{share}`")
        lines.append("")

    lines += [
        "## 5. E2E bridge placeholders",
        f"- e2e_bridge.schema_version: `{payload['e2e_bridge']['schema_version']}`",
        f"- e2e_bridge.status: `{payload['e2e_bridge']['status']}`",
        "- system_timestamps: reserved for chain-level run / submit-window / finality observation UTC timestamps",
        "- per-workload placeholders carry null metrics until real E2E instrumentation lands; null is intentionally 'not measured', never synthetic data",
        "",
        "## 6. E2E mapping template",
        "- submit_tps: client accepted tx / observation window",
        "- finalized_tps: finalized tx / observation window",
        "- finality_p50_ms / p95 / p99: submit→finalized latency",
        "- drop_rate / retry_rate / rollback_rate: ingress + execution quality",
        "- scheduler_window_share: attach this artifact's per-workload share as execution-kernel budget component",
        "- bottleneck_segment: whichever segment dominates after E2E timestamps are added",
        "- segment_latency_ms[*]: client_submit / mempool_queue / consensus / scheduler_grouping / execution / commit / storage / finality_observation",
        "",
        "## 7. Repro commands",
        "```bash",
        "cd trillionnium",
        "./scripts/run_bench_regression_matrix.sh",
        "python3 ./scripts/render_benchmark_closeout.py",
        "```",
        "",
        "## 8. Machine-readable artifact",
        f"- JSON: `{out_json}`",
    ]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Render TRNM benchmark closeout artifacts from regression CSV")
    ap.add_argument("--csv", default=None, help="bench-regression-matrix csv path")
    ap.add_argument("--out-dir", default=None, help="output directory (default: run/bench/closeout-<ts>)")
    ap.add_argument("--profile-id", default="week7-e2e-closeout-v1")
    ap.add_argument("--measurement-window", default="single-run matrix snapshot; compare only inside same hardware/profile")
    ap.add_argument("--warmup-policy", default="cargo artifacts reused; no extra warmup beyond script defaults")
    ap.add_argument("--target-tps", nargs="*", type=int, default=DEFAULT_TARGET_TPS)
    args = ap.parse_args()

    csv_path = Path(args.csv) if args.csv else Path(latest(str(BENCH_DIR / "bench-regression-matrix-*.csv")) or "")
    if not csv_path or not csv_path.exists():
        raise SystemExit("no regression csv found")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else BENCH_DIR / f"closeout-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_rows(csv_path)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "regression_csv": str(csv_path),
        },
        "git": {
            "branch": git_branch(ROOT),
            "head": git_head(ROOT),
        },
        "hardware": detect_hardware(),
        "benchmark_profile": {
            "profile_id": args.profile_id,
            "measurement_window": args.measurement_window,
            "warmup_policy": args.warmup_policy,
            "target_tps_windows": args.target_tps,
            "workload_family": ["classic", "mixed", "hot-streak"],
            "disclaimer": "micro_scheduler_ceiling_tps is not chain TPS",
        },
        "summary": build_summary(rows, args.target_tps),
        "e2e_mapping_template": {
            "required_fields": [
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
            ],
            "segment_order": SEGMENT_ORDER,
        },
    }
    payload["e2e_bridge"] = build_e2e_bridge(payload["summary"], SEGMENT_ORDER)

    out_json = out_dir / "benchmark-closeout.json"
    out_md = out_dir / "benchmark-closeout.md"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(render_md(payload, out_json), encoding="utf-8")

    print(out_json)
    print(out_md)


if __name__ == "__main__":
    main()
