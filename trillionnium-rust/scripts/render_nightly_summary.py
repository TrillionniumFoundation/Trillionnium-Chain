#!/usr/bin/env python3
import csv
import glob
import os
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HEALTH = os.path.join(ROOT, "run", "health")
OUT = os.environ.get("NIGHTLY_SUMMARY_OUT") or os.path.join(
    HEALTH, f"nightly-summary-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
)
os.makedirs(HEALTH, exist_ok=True)


def latest(pattern: str):
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def parse_kv(path: str):
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def iv(v):
    try:
        return int(float(v))
    except Exception:
        return 0


def parse_aggr_stage_stats(path: str):
    if not path or not os.path.exists(path):
        return {}, set()

    by_workload = {}
    strategy_sources = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get("strategy") != "aggressive-greedy":
                continue
            src = (r.get("strategy_source") or "unknown").strip()
            strategy_sources.add(src)
            wl = r.get("workload", "unknown")
            d = by_workload.setdefault(
                wl,
                {
                    "rows": 0,
                    "ww_checks": 0,
                    "ww_hits": 0,
                    "wr_checks": 0,
                    "wr_hits": 0,
                    "rw_checks": 0,
                    "rw_hits": 0,
                },
            )
            d["rows"] += 1
            d["ww_checks"] += iv(r.get("stage_ww_checks", 0))
            d["ww_hits"] += iv(r.get("stage_ww_hits", 0))
            d["wr_checks"] += iv(r.get("stage_wr_checks", 0))
            d["wr_hits"] += iv(r.get("stage_wr_hits", 0))
            d["rw_checks"] += iv(r.get("stage_rw_checks", 0))
            d["rw_hits"] += iv(r.get("stage_rw_hits", 0))

    return by_workload, strategy_sources


def rate(hits, checks):
    return 0.0 if checks <= 0 else hits / checks


attrib_file = os.environ.get("NIGHTLY_ATTRIBUTION_FILE") or latest(
    os.path.join(HEALTH, "nightly-attribution-*.txt")
)
suggest_file = os.environ.get("AUTO_ADAPTIVE_SUGGESTION_FILE") or latest(
    os.path.join(HEALTH, "auto-adaptive-threshold-suggestion-*.txt")
)
regression_csv = os.environ.get("BENCH_REGRESSION_CSV") or latest(
    os.path.join(ROOT, "run", "bench", "bench-regression-matrix-*.csv")
)
a = parse_kv(attrib_file)
s = parse_kv(suggest_file)
stage_stats, strategy_sources = parse_aggr_stage_stats(regression_csv)

labels = a.get("attribution.labels", "unknown")
reasons = a.get("attribution.reasons", "none")
m2_gate_log = a.get("m2.policy_gate.log", "none")
m2_default_drift_guard = a.get("m2.policy_gate.assert_default_drift_guard", "unknown")

lines = []
lines.append("# Nightly Health Summary")
lines.append("")
lines.append(f"- Labels: `{labels}`")
lines.append(f"- Reasons: `{reasons}`")
lines.append(
    f"- Attribution artifact: `{attrib_file or 'missing'}`"
)
lines.append(
    f"- Suggestion artifact: `{suggest_file or 'missing'}`"
)
lines.append(
    f"- Regression matrix artifact: `{regression_csv or 'missing'}`"
)
lines.append("")
lines.append("## M2 policy gate signal")
lines.append(f"- default-drift guard assertion: `{m2_default_drift_guard}`")
lines.append(f"- gate log: `{m2_gate_log}`")
if m2_default_drift_guard != "pass":
    lines.append("- failure_signal: `m2_policy_gate_default_drift_guard_not_pass`")
lines.append("")
lines.append("## Auto-adaptive decision snapshot")
lines.append(f"- Mixed: `{a.get('strategy_exp.auto.reason', 'unknown')}` (use_hot={a.get('strategy_exp.auto.use_hot_bucket', 'unknown')})")
lines.append(f"- Hotspot: `{a.get('hotspot_exp.auto.reason', 'unknown')}` (use_hot={a.get('hotspot_exp.auto.use_hot_bucket', 'unknown')})")
lines.append(f"- Mixed elapsed: original={a.get('strategy_exp.elapsed.original_ms', 'n/a')}ms / auto={a.get('strategy_exp.elapsed.auto_ms', 'n/a')}ms")
lines.append(f"- Hotspot elapsed: original={a.get('hotspot_exp.elapsed.original_ms', 'n/a')}ms / auto={a.get('hotspot_exp.elapsed.auto_ms', 'n/a')}ms")
lines.append("")
lines.append("## Threshold suggestion")
if s:
    lines.append(f"- Recommended: `{s.get('suggest.recommended', 'false')}`")
    lines.append(f"- Current: streak={s.get('current.streak_ratio', 'n/a')}, margin={s.get('current.min_margin', 'n/a')}, hot_share={s.get('current.min_hot_key_share', 'n/a')}")
    lines.append(f"- Suggest: streak={s.get('suggest.streak_ratio', 'n/a')}, margin={s.get('suggest.min_margin', 'n/a')}, hot_share={s.get('suggest.min_hot_key_share', 'n/a')}")
else:
    lines.append("- No suggestion artifact found")

lines.append("")
lines.append("## Aggressive stage hit-rate snapshot")
if stage_stats:
    if regression_csv:
        lines.append(f"- Source: `{regression_csv}`")
    if strategy_sources:
        lines.append(f"- strategy_source: `{','.join(sorted(strategy_sources))}`")
    for wl in sorted(stage_stats.keys()):
        d = stage_stats[wl]
        lines.append(
            "- {} (rows={}): WW={:.4f} ({}/{}), WR={:.4f} ({}/{}), RW={:.4f} ({}/{})".format(
                wl,
                d["rows"],
                rate(d["ww_hits"], d["ww_checks"]),
                d["ww_hits"],
                d["ww_checks"],
                rate(d["wr_hits"], d["wr_checks"]),
                d["wr_hits"],
                d["wr_checks"],
                rate(d["rw_hits"], d["rw_checks"]),
                d["rw_hits"],
                d["rw_checks"],
            )
        )
else:
    lines.append("- No regression matrix with stage counters found")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print(f"[OK] nightly summary: {OUT}")
