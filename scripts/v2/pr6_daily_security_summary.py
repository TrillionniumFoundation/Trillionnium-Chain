#!/usr/bin/env python3
"""Generate PR-6 nightly daily security summary.

Output:
- run/pr6-ops/daily-security-summary.md
"""

from __future__ import annotations

import glob
import json
import os
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT_DIR = os.path.join(ROOT, "run", "pr6-ops")
OUT_MD = os.path.join(OUT_DIR, "daily-security-summary.md")

RUST_ROOT = os.path.join(ROOT, "trillionnium")
RUST_HEALTH = os.path.join(RUST_ROOT, "run", "health")
RUST_BENCH = os.path.join(RUST_ROOT, "run", "bench")
PR5_ROOT = os.path.join(ROOT, "run", "pr5-reconcile")
PR7_TOPN_ROOT = os.path.join(ROOT, "run", "pr7-topn")
PR7_ALERT_STATE = os.environ.get("ALERT_NOTIFY_STATE_FILE", os.path.join(ROOT, "run", "pr7-alert-delivery", "state.json"))


def latest(pattern: str) -> str | None:
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def parse_kv(path: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def parse_json(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def parse_pr5_summary(path: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("day="):
                chunks = line.split()
                for c in chunks:
                    if "=" in c:
                        k, v = c.split("=", 1)
                        out[k] = v
            elif "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def file_count(pattern: str) -> int:
    return len(glob.glob(pattern))


attrib_file = os.environ.get("NIGHTLY_ATTRIBUTION_FILE") or latest(os.path.join(RUST_HEALTH, "nightly-attribution-*.txt"))
nightly_summary = os.environ.get("NIGHTLY_SUMMARY_FILE") or latest(os.path.join(RUST_HEALTH, "nightly-summary-*.md"))
suggest_file = os.environ.get("AUTO_ADAPTIVE_SUGGESTION_FILE") or latest(os.path.join(RUST_HEALTH, "auto-adaptive-threshold-suggestion-*.txt"))
aggr_profile = latest(os.path.join(RUST_BENCH, "aggressive-profile-summary-*.md"))
pr5_summary_file = latest(os.path.join(PR5_ROOT, "*", "summary.txt"))
pr7_topn_summary = latest(os.path.join(PR7_TOPN_ROOT, "*", "topn-anomaly-summary.md"))

attrib = parse_kv(attrib_file)
suggest = parse_kv(suggest_file)
pr5 = parse_pr5_summary(pr5_summary_file)
alert_state = parse_json(PR7_ALERT_STATE)
alert_stats = alert_state.get("stats", {}) if isinstance(alert_state, dict) else {}
last_delivery = alert_state.get("last_delivery", {}) if isinstance(alert_state, dict) else {}

labels = attrib.get("attribution.labels", "unknown")
reasons = attrib.get("attribution.reasons", "n/a")

alerts: list[str] = []
if labels not in ("green", "healthy", "unknown"):
    alerts.append(f"nightly attribution label is `{labels}`")
if pr5 and pr5.get("status") != "PASS":
    alerts.append(f"pr5 reconcile status is `{pr5.get('status', 'unknown')}`")
if not pr5_summary_file:
    alerts.append("missing PR-5 reconcile summary artifact")
if not attrib_file:
    alerts.append("missing nightly attribution artifact")
if not nightly_summary:
    alerts.append("missing rendered nightly summary artifact")
if not pr7_topn_summary:
    alerts.append("missing PR-7 TopN anomaly summary artifact")

now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
os.makedirs(OUT_DIR, exist_ok=True)

lines: list[str] = []
lines.append("# PR-6 Daily Security Summary")
lines.append("")
lines.append(f"- generated_at_utc: `{now}`")
lines.append(f"- git_sha: `{os.getenv('GITHUB_SHA', 'local')}`")
lines.append(f"- workflow_run_id: `{os.getenv('GITHUB_RUN_ID', 'local')}`")
lines.append("")
lines.append("## Key Metrics")
lines.append(f"- nightly.attribution.labels: `{labels}`")
lines.append(f"- nightly.attribution.reasons: `{reasons}`")
lines.append(f"- nightly.summary.present: `{str(bool(nightly_summary)).lower()}`")
lines.append(f"- nightly.suggestion.present: `{str(bool(suggest_file)).lower()}`")
lines.append(f"- aggressive.profile.present: `{str(bool(aggr_profile)).lower()}`")
lines.append(f"- pr5.reconcile.status: `{pr5.get('status', 'MISSING')}`")
lines.append(f"- pr5.reconcile.record_count: `{pr5.get('record_count', 'n/a')}`")
lines.append(f"- pr5.reconcile.challenge_events: `{pr5.get('challenge_events', 'n/a')}`")
lines.append(f"- pr5.reconcile.resolve_events: `{pr5.get('resolve_events', 'n/a')}`")
lines.append(f"- pr5.reconcile.forfeited: `{pr5.get('forfeited', 'n/a')}`")
lines.append(f"- pr5.reconcile.refunded: `{pr5.get('refunded', 'n/a')}`")
lines.append(f"- pr5.reconcile.treasury_delta_sum: `{pr5.get('treasury_delta_sum', 'n/a')}`")
lines.append(f"- pr5.reconcile.challenger_delta_sum: `{pr5.get('challenger_delta_sum', 'n/a')}`")
lines.append(f"- pr7.topn.summary.present: `{str(bool(pr7_topn_summary)).lower()}`")
lines.append(f"- pr7.alert_delivery.alerts_sent: `{alert_stats.get('alerts_sent', 0)}`")
lines.append(f"- pr7.alert_delivery.alerts_suppressed: `{alert_stats.get('alerts_suppressed', 0)}`")
lines.append(f"- pr7.alert_delivery.alerts_failed: `{alert_stats.get('alerts_failed', 0)}`")
lines.append("")
lines.append("## Alerts")
if alerts:
    for a in alerts:
        lines.append(f"- ⚠️ {a}")
else:
    lines.append("- ✅ no critical alert detected in summary scope")

lines.append("")
lines.append("## Latest Alert Delivery")
if isinstance(last_delivery, dict) and last_delivery:
    lines.append(f"- last_delivery.event: `{last_delivery.get('event', 'n/a')}`")
    lines.append(f"- last_delivery.reason: `{last_delivery.get('reason', 'n/a')}`")
    lines.append(f"- last_delivery.channel: `{last_delivery.get('channel', 'n/a')}`")
    lines.append(f"- last_delivery.report_status: `{last_delivery.get('report_status', 'n/a')}`")
    lines.append(f"- last_delivery.at_utc: `{last_delivery.get('at_utc', 'n/a')}`")
else:
    lines.append("- last_delivery.event: `n/a`")
    lines.append("- last_delivery.reason: `n/a`")

if suggest:
    lines.append("")
    lines.append("## Threshold Suggestion Snapshot")
    lines.append(f"- suggest.recommended: `{suggest.get('suggest.recommended', 'n/a')}`")
    lines.append(
        f"- current(streak/margin/hot_share): `{suggest.get('current.streak_ratio', 'n/a')}` / `{suggest.get('current.min_margin', 'n/a')}` / `{suggest.get('current.min_hot_key_share', 'n/a')}`"
    )
    lines.append(
        f"- suggest(streak/margin/hot_share): `{suggest.get('suggest.streak_ratio', 'n/a')}` / `{suggest.get('suggest.min_margin', 'n/a')}` / `{suggest.get('suggest.min_hot_key_share', 'n/a')}`"
    )

lines.append("")
lines.append("## Artifact Pointers")
lines.append(f"- nightly_attribution: `{attrib_file or 'MISSING'}`")
lines.append(f"- nightly_summary: `{nightly_summary or 'MISSING'}`")
lines.append(f"- threshold_suggestion: `{suggest_file or 'MISSING'}`")
lines.append(f"- aggressive_profile_summary: `{aggr_profile or 'MISSING'}`")
lines.append(f"- pr5_reconcile_summary: `{pr5_summary_file or 'MISSING'}`")
lines.append(f"- pr5_reconcile_runs_total: `{file_count(os.path.join(PR5_ROOT, '*', 'summary.txt'))}`")
lines.append(f"- pr7_topn_anomaly_summary: `{pr7_topn_summary or 'MISSING'}`")
lines.append(f"- pr7_topn_runs_total: `{file_count(os.path.join(PR7_TOPN_ROOT, '*', 'topn-anomaly-summary.md'))}`")
lines.append(f"- pr7_alert_delivery_state: `{PR7_ALERT_STATE if os.path.exists(PR7_ALERT_STATE) else 'MISSING'}`")

with open(OUT_MD, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print(f"[OK] wrote {OUT_MD}")
