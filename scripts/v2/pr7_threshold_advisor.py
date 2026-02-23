#!/usr/bin/env python3
"""PR-7: 7-day trend threshold advisor for challenge alert rules.

Reads historical artifacts from:
- run/pr5-reconcile/*/(reconcile-report.txt|summary.txt|reconcile.json)
- run/pr6-ops/*.txt|*.json|*.md (focus: pr6-alert-rules-gate.txt)

Outputs:
- machine-readable JSON suggestion
- human-readable Markdown summary
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import math
import os
from collections import defaultdict
from pathlib import Path

DEFAULTS = {
    "unresolved": {"warn": 3, "fail": 5},
    "forfeits_daily_increase": {"warn": 70, "fail": 100},
    "escrow_nonzero_hours": {"warn": 16.0, "fail": 24.0},
}


def parse_kv_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def to_int(v: str | None, default: int = 0) -> int:
    if v is None:
        return default
    try:
        return int(float(v))
    except Exception:
        return default


def to_float(v: str | None, default: float = 0.0) -> float:
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    arr = sorted(float(x) for x in values)
    rank = (len(arr) - 1) * p
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return arr[lo]
    frac = rank - lo
    return arr[lo] * (1 - frac) + arr[hi] * frac


def clamp_warn_fail(warn: float, fail: float) -> tuple[float, float]:
    fail = max(fail, 1.0)
    warn = max(1.0, warn)
    if warn >= fail:
        warn = max(1.0, fail - 1)
    return warn, fail


def load_pr5_timeseries(pr5_root: Path, start_day: dt.date) -> dict[str, dict[str, float]]:
    """Return day -> metrics from reconcile artifacts.

    metrics:
      unresolved (carry_out_open)
      forfeits_total_day (forfeited_total)
    """
    day_map: dict[str, dict[str, float]] = defaultdict(dict)

    # Prefer reconcile-report.txt (contains carry_out_open and forfeited_total amount)
    for p in sorted(glob.glob(str(pr5_root / "*" / "reconcile-report.txt"))):
        kv = parse_kv_file(p)
        gen = kv.get("generated_at", "")
        day = None
        if gen:
            try:
                day = dt.datetime.fromisoformat(gen).date().isoformat()
            except Exception:
                day = None
        if not day:
            day = dt.datetime.fromtimestamp(os.path.getmtime(p), tz=dt.timezone.utc).date().isoformat()

        if day < start_day.isoformat():
            continue

        day_map[day]["unresolved"] = float(to_int(kv.get("carry_out_open"), 0))
        day_map[day]["forfeits_total_day"] = float(to_int(kv.get("forfeited_total"), 0))

    # Fallback from summary.txt when reconcile-report absent
    if not day_map:
        for p in sorted(glob.glob(str(pr5_root / "*" / "summary.txt"))):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("day="):
                        continue
                    chunks = dict(tok.split("=", 1) for tok in line.split() if "=" in tok)
                    day = chunks.get("day")
                    if not day or day < start_day.isoformat():
                        continue
                    day_map[day]["unresolved"] = float(to_int(chunks.get("challenge_events"), 0) - to_int(chunks.get("resolve_events"), 0))
                    day_map[day]["forfeits_total_day"] = float(to_int(chunks.get("forfeited"), 0))

    return dict(sorted(day_map.items()))


def load_pr6_baseline(pr6_ops_root: Path) -> dict:
    gate = pr6_ops_root / "pr6-alert-rules-gate.txt"
    out = {
        "current_value": {
            "unresolved": 0,
            "forfeits_daily_increase": 0,
            "escrow_nonzero_hours": 0.0,
        },
        "threshold": {
            "unresolved": DEFAULTS["unresolved"].copy(),
            "forfeits_daily_increase": DEFAULTS["forfeits_daily_increase"].copy(),
            "escrow_nonzero_hours": DEFAULTS["escrow_nonzero_hours"].copy(),
        },
        "source": str(gate),
        "exists": gate.exists(),
    }
    if not gate.exists():
        return out

    kv = parse_kv_file(str(gate))
    out["current_value"]["unresolved"] = to_int(kv.get("rule.unresolved_challenges.value"), 0)
    out["current_value"]["forfeits_daily_increase"] = to_int(kv.get("rule.forfeits_daily_increase.value"), 0)
    out["current_value"]["escrow_nonzero_hours"] = to_float(kv.get("rule.escrow_nonzero_hours.value"), 0.0)

    out["threshold"]["unresolved"] = {
        "warn": to_int(kv.get("rule.unresolved_challenges.warn_threshold"), DEFAULTS["unresolved"]["warn"]),
        "fail": to_int(kv.get("rule.unresolved_challenges.fail_threshold"), DEFAULTS["unresolved"]["fail"]),
    }
    out["threshold"]["forfeits_daily_increase"] = {
        "warn": to_int(kv.get("rule.forfeits_daily_increase.warn_threshold"), DEFAULTS["forfeits_daily_increase"]["warn"]),
        "fail": to_int(kv.get("rule.forfeits_daily_increase.fail_threshold"), DEFAULTS["forfeits_daily_increase"]["fail"]),
    }
    out["threshold"]["escrow_nonzero_hours"] = {
        "warn": to_float(kv.get("rule.escrow_nonzero_hours.warn_threshold"), DEFAULTS["escrow_nonzero_hours"]["warn"]),
        "fail": to_float(kv.get("rule.escrow_nonzero_hours.fail_threshold"), DEFAULTS["escrow_nonzero_hours"]["fail"]),
    }
    return out


def suggest_rule(name: str, samples: list[float], baseline_warn: float, baseline_fail: float, min_days: int) -> dict:
    if len(samples) < min_days:
        return {
            "warn": baseline_warn,
            "fail": baseline_fail,
            "mode": "conservative_default",
            "reason": f"insufficient_data: samples={len(samples)} < min_days={min_days}",
            "stats": {"count": len(samples)},
        }

    p95 = percentile(samples, 0.95)
    p50 = percentile(samples, 0.50)
    peak = max(samples) if samples else 0.0

    # Keep conservative buffer above observed tail.
    suggested_fail = max(baseline_fail, math.ceil(max(peak, p95 * 1.25)))
    suggested_warn = max(baseline_warn, math.floor(suggested_fail * 0.7))
    suggested_warn, suggested_fail = clamp_warn_fail(suggested_warn, suggested_fail)

    return {
        "warn": suggested_warn,
        "fail": suggested_fail,
        "mode": "trend_based",
        "reason": "7d trend with tail buffer (p95*1.25, floor=baseline)",
        "stats": {
            "count": len(samples),
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "peak": round(float(peak), 3),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="PR-7 7-day threshold advisor")
    ap.add_argument("--pr5-root", default="run/pr5-reconcile", help="PR5 artifact root")
    ap.add_argument("--pr6-ops-root", default="run/pr6-ops", help="PR6 ops artifact root")
    ap.add_argument("--lookback-days", type=int, default=7, help="trend window in days")
    ap.add_argument("--min-days", type=int, default=3, help="minimum sample days for trend-based suggestion")
    ap.add_argument("--out-dir", default="", help="output dir; default run/pr7-threshold-advisor/<timestamp>")
    args = ap.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    ts = now.strftime("%Y%m%d-%H%M%S")
    start_day = (now - dt.timedelta(days=args.lookback_days - 1)).date()

    root = Path.cwd()
    pr5_root = (root / args.pr5_root).resolve()
    pr6_ops_root = (root / args.pr6_ops_root).resolve()

    out_dir = Path(args.out_dir) if args.out_dir else (root / "run" / "pr7-threshold-advisor" / ts)
    out_dir.mkdir(parents=True, exist_ok=True)

    pr5_day = load_pr5_timeseries(pr5_root, start_day=start_day)
    pr6 = load_pr6_baseline(pr6_ops_root)

    ordered_days = sorted(pr5_day.keys())
    unresolved_samples = [pr5_day[d].get("unresolved", 0.0) for d in ordered_days]
    forfeits_total = [pr5_day[d].get("forfeits_total_day", 0.0) for d in ordered_days]
    forfeits_inc = [max(0.0, forfeits_total[i] - forfeits_total[i - 1]) for i in range(1, len(forfeits_total))]

    escrow_samples: list[float] = []
    if pr6["exists"]:
        escrow_samples.append(float(pr6["current_value"]["escrow_nonzero_hours"]))

    s_unresolved = suggest_rule(
        "unresolved",
        unresolved_samples,
        baseline_warn=float(pr6["threshold"]["unresolved"]["warn"]),
        baseline_fail=float(pr6["threshold"]["unresolved"]["fail"]),
        min_days=args.min_days,
    )
    s_forfeits = suggest_rule(
        "forfeits_daily_increase",
        forfeits_inc,
        baseline_warn=float(pr6["threshold"]["forfeits_daily_increase"]["warn"]),
        baseline_fail=float(pr6["threshold"]["forfeits_daily_increase"]["fail"]),
        min_days=max(2, args.min_days - 1),  # increase series has one fewer point
    )
    s_escrow = suggest_rule(
        "escrow_nonzero_hours",
        escrow_samples,
        baseline_warn=float(pr6["threshold"]["escrow_nonzero_hours"]["warn"]),
        baseline_fail=float(pr6["threshold"]["escrow_nonzero_hours"]["fail"]),
        min_days=args.min_days,
    )

    result = {
        "status": "PASS",
        "advisor": "PR7_THRESHOLD_ADVISOR",
        "generated_at_utc": now.isoformat(),
        "window": {
            "lookback_days": args.lookback_days,
            "start_day_utc": start_day.isoformat(),
            "end_day_utc": now.date().isoformat(),
        },
        "inputs": {
            "pr5_root": str(pr5_root),
            "pr6_ops_root": str(pr6_ops_root),
            "pr5_days_found": ordered_days,
            "pr6_gate_source": pr6["source"],
        },
        "observed": {
            "unresolved_daily": [{"day": d, "value": pr5_day[d].get("unresolved", 0.0)} for d in ordered_days],
            "forfeits_total_daily": [{"day": d, "value": pr5_day[d].get("forfeits_total_day", 0.0)} for d in ordered_days],
            "forfeits_daily_increase": [{"day": ordered_days[i], "value": forfeits_inc[i - 1]} for i in range(1, len(ordered_days))],
            "escrow_nonzero_hours_samples": escrow_samples,
        },
        "baseline_thresholds": pr6["threshold"],
        "suggestions": {
            "unresolved_challenges": s_unresolved,
            "forfeits_daily_increase": s_forfeits,
            "escrow_nonzero_hours": s_escrow,
        },
    }

    out_json = out_dir / "threshold-advice.json"
    out_md = out_dir / "threshold-advice.md"
    out_json.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    md = [
        "# PR-7 Threshold Advisor (7-day)",
        "",
        f"- generated_at_utc: `{result['generated_at_utc']}`",
        f"- window: `{result['window']['start_day_utc']} .. {result['window']['end_day_utc']}` ({args.lookback_days}d)",
        f"- pr5_days_found: `{len(ordered_days)}`",
        "",
        "## Suggested Thresholds",
        "",
        "| rule | warn | fail | mode | reason |",
        "|---|---:|---:|---|---|",
        f"| unresolved_challenges | {s_unresolved['warn']} | {s_unresolved['fail']} | {s_unresolved['mode']} | {s_unresolved['reason']} |",
        f"| forfeits_daily_increase | {s_forfeits['warn']} | {s_forfeits['fail']} | {s_forfeits['mode']} | {s_forfeits['reason']} |",
        f"| escrow_nonzero_hours | {s_escrow['warn']} | {s_escrow['fail']} | {s_escrow['mode']} | {s_escrow['reason']} |",
        "",
        "## Rationale",
        "",
        "- unresolved_challenges: derived from PR5 `carry_out_open` per day; when data insufficient, keep PR6 conservative baseline.",
        "- forfeits_daily_increase: derived from day-over-day increase of PR5 `forfeited_total`; sparse history falls back to baseline.",
        "- escrow_nonzero_hours: sourced from PR6 ops gate samples; if <min_days, keep conservative baseline.",
        "",
        "## Data Pointers",
        f"- PR5 root: `{pr5_root}`",
        f"- PR6 ops root: `{pr6_ops_root}`",
        f"- PR6 gate: `{pr6['source']}`",
        f"- JSON: `{out_json}`",
    ]
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"[OK] wrote {out_json}")
    print(f"[OK] wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
