#!/usr/bin/env python3
"""P11 policy rollback guard (dry-run).

Rules (1h window by default):
- failed_rate > 20%
- consecutive_failures > 10
- critical alerts failed > 0

Output:
- Human-readable status line with PASS/WARN/FAIL
- Explicit `would-rollback` text (dry-run only)
- Optional machine-readable JSON artifact
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


def parse_utc_ts(raw: str | None) -> int | None:
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return int(dt.datetime.fromisoformat(s).timestamp())
    except ValueError:
        return None


def safe_read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        return {}


def safe_read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except json.JSONDecodeError:
            continue
    return out


def safe_nonneg_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def parse_audit_events(path: Path, since_ts: int) -> list[tuple[int, bool]]:
    """Return (ts, success) sorted by time asc.

    Prefer PR7 `record_type=delivery_summary` rows when present (per-alert outcome).
    Fallback to legacy per-channel rows for backward compatibility.
    Excludes policy rejections (`rejected=true`) and non-delivery records (`attempts<=0`).
    """
    summary_events: list[tuple[int, bool]] = []
    legacy_events: list[tuple[int, bool]] = []
    for rec in safe_read_jsonl(path):
        ts = parse_utc_ts(str(rec.get("at_utc", "")))
        if ts is None or ts < since_ts:
            continue
        if bool(rec.get("rejected", False)):
            continue
        if "attempts" in rec:
            attempts = safe_nonneg_int(rec.get("attempts", 0), default=0)
            if attempts <= 0:
                continue
        ok = bool(rec.get("ok", False))
        if str(rec.get("record_type", "")).strip() == "delivery_summary":
            summary_events.append((ts, ok))
        else:
            legacy_events.append((ts, ok))
    events = summary_events if summary_events else legacy_events
    events.sort(key=lambda x: x[0])
    return events


def consecutive_failures_from_audit(path: Path, since_ts: int) -> int | None:
    if not path.exists():
        return None
    events = parse_audit_events(path, since_ts)
    if not events:
        return 0
    streak = 0
    for _ts, ok in reversed(events):
        if ok:
            break
        streak += 1
    return streak


def main() -> int:
    ap = argparse.ArgumentParser(description="P11 dry-run policy rollback guard")
    ap.add_argument("--state-file", default="run/pr7-alert-delivery/state.json")
    ap.add_argument("--dead-letter-file", default="run/pr7-alert-delivery/dead-letter.jsonl")
    ap.add_argument("--audit-file", default="run/pr7-alert-delivery/audit.jsonl")
    ap.add_argument("--lookback-seconds", type=int, default=3600)
    ap.add_argument("--failed-rate-threshold-pct", type=float, default=20.0)
    ap.add_argument("--consecutive-failures-threshold", type=int, default=10)
    ap.add_argument("--out", default="run/pr11/policy-rollback-guard.txt")
    ap.add_argument("--json-out", default="run/pr11/policy-rollback-guard.json")
    ap.add_argument("--policy-tag", default="alert-policy/current")
    args = ap.parse_args()

    now_utc = dt.datetime.now(dt.timezone.utc)
    now_ts = int(now_utc.timestamp())
    since_ts = now_ts - max(1, args.lookback_seconds)

    state_path = Path(args.state_file)
    dead_path = Path(args.dead_letter_file)
    audit_path = Path(args.audit_file)

    state = safe_read_json(state_path)
    dead = safe_read_jsonl(dead_path)

    stats = state.get("stats", {}) if isinstance(state.get("stats"), dict) else {}
    sent_state = safe_nonneg_int(stats.get("alerts_sent", 0), default=0)
    failed_state = safe_nonneg_int(stats.get("alerts_failed", 0), default=0)
    suppressed_state = safe_nonneg_int(stats.get("alerts_suppressed", 0), default=0)

    # Windowed dead-letter sample (1h) for critical failure count and rate fallback.
    dead_1h = []
    for rec in dead:
        ts = parse_utc_ts(str(rec.get("created_at_utc", "")))
        if ts is None or ts < since_ts:
            continue
        dead_1h.append(rec)

    critical_failed_1h = 0
    for rec in dead_1h:
        level = str(rec.get("level", "")).strip().upper()
        status = str(rec.get("status", "")).strip().upper()
        msg = str(rec.get("message", "")).upper()
        if level == "CRITICAL" or status == "FAIL" or "[CRITICAL]" in msg:
            critical_failed_1h += 1

    # failed_rate guard must use lookback-window samples (not lifetime cumulative counters),
    # otherwise old history can dilute recent incident spikes.
    audit_events_1h = parse_audit_events(audit_path, since_ts)
    audit_total_1h = len(audit_events_1h)
    audit_failed_1h = sum(1 for _ts, ok in audit_events_1h if not ok)

    failed_rate_basis = "audit_window"
    failed_samples_total = audit_total_1h
    failed_samples_failed = audit_failed_1h

    if failed_samples_total == 0 and len(dead_1h) > 0:
        # Conservative fallback: if no audit stream, dead-letter in window implies failed attempts.
        failed_rate_basis = "dead_letter_window_fallback"
        failed_samples_total = len(dead_1h)
        failed_samples_failed = len(dead_1h)

    failed_rate_pct = (
        100.0 * failed_samples_failed / failed_samples_total if failed_samples_total > 0 else 0.0
    )

    consecutive_failures = consecutive_failures_from_audit(audit_path, since_ts)
    degraded_notes: list[str] = []
    if consecutive_failures is None:
        # Fallback when no audit stream exists: dead-letter consecutive in lookback.
        consecutive_failures = len(dead_1h)
        degraded_notes.append("audit file missing; consecutive_failures approximated from dead-letter count in window")
    if failed_rate_basis != "audit_window":
        degraded_notes.append("audit window samples missing; failed_rate derived from dead-letter window fallback")

    reasons_fail: list[str] = []
    reasons_warn: list[str] = []

    if failed_rate_pct > args.failed_rate_threshold_pct:
        reasons_fail.append(
            f"failed_rate={failed_rate_pct:.2f}% > {args.failed_rate_threshold_pct:.2f}% (basis={failed_rate_basis})"
        )
    if consecutive_failures > args.consecutive_failures_threshold:
        reasons_fail.append(
            f"consecutive_failures={consecutive_failures} > {args.consecutive_failures_threshold} (window={args.lookback_seconds}s)"
        )
    if critical_failed_1h > 0:
        reasons_fail.append(f"critical_alerts_failed_1h={critical_failed_1h} > 0")

    if failed_samples_total == 0:
        reasons_warn.append("no delivery samples in lookback window")
    if not state_path.exists():
        reasons_warn.append(f"state file missing: {state_path}")
    if not dead_path.exists():
        reasons_warn.append(f"dead-letter file missing: {dead_path}")
    reasons_warn.extend(degraded_notes)

    if reasons_fail:
        status = "FAIL"
    elif reasons_warn:
        status = "WARN"
    else:
        status = "PASS"

    would_rollback = status == "FAIL"
    rollback_text = (
        f"would-rollback: YES (dry-run) policy={args.policy_tag}"
        if would_rollback
        else f"would-rollback: NO policy={args.policy_tag}"
    )

    lines: list[str] = []
    lines.append(f"generated_at_utc={now_utc.isoformat()}")
    lines.append(f"status={status}")
    lines.append("mode=dry-run")
    lines.append(f"lookback_seconds={args.lookback_seconds}")
    lines.append(f"failed_rate_pct={failed_rate_pct:.2f}")
    lines.append(f"failed_rate_basis={failed_rate_basis}")
    lines.append(f"failed_rate_threshold_pct={args.failed_rate_threshold_pct:.2f}")
    lines.append(f"consecutive_failures={consecutive_failures}")
    lines.append(f"consecutive_failures_threshold={args.consecutive_failures_threshold}")
    lines.append(f"critical_alerts_failed_1h={critical_failed_1h}")
    lines.append(f"samples_total={failed_samples_total}")
    lines.append(f"samples_failed={failed_samples_failed}")
    lines.append(f"samples_state_sent={sent_state}")
    lines.append(f"samples_state_suppressed={suppressed_state}")
    lines.append(f"samples_state_failed={failed_state}")
    lines.append(f"audit_events_1h={audit_total_1h}")
    lines.append(f"dead_letter_events_1h={len(dead_1h)}")
    lines.append(rollback_text)

    if reasons_fail:
        for i, r in enumerate(reasons_fail, 1):
            lines.append(f"fail_reason.{i}={r}")
    if reasons_warn:
        for i, r in enumerate(reasons_warn, 1):
            lines.append(f"warn_reason.{i}={r}")

    summary = f"[P11][{status}] {rollback_text}"
    print(summary)
    for r in reasons_fail:
        print(f"- FAIL: {r}")
    for r in reasons_warn:
        print(f"- WARN: {r}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    payload = {
        "generated_at_utc": now_utc.isoformat(),
        "status": status,
        "mode": "dry-run",
        "policy_tag": args.policy_tag,
        "would_rollback": would_rollback,
        "rules": {
            "failed_rate": {
                "value_pct": round(failed_rate_pct, 4),
                "basis": failed_rate_basis,
                "threshold_pct": args.failed_rate_threshold_pct,
                "triggered": failed_rate_pct > args.failed_rate_threshold_pct,
            },
            "consecutive_failures": {
                "value": consecutive_failures,
                "threshold": args.consecutive_failures_threshold,
                "triggered": consecutive_failures > args.consecutive_failures_threshold,
            },
            "critical_alerts_failed_1h": {
                "value": critical_failed_1h,
                "threshold": 0,
                "triggered": critical_failed_1h > 0,
            },
        },
        "samples": {
            "total": failed_samples_total,
            "failed": failed_samples_failed,
            "audit_1h": audit_total_1h,
            "dead_letter_1h": len(dead_1h),
            "state_sent": sent_state,
            "state_suppressed": suppressed_state,
            "state_failed": failed_state,
        },
        "reasons": {
            "fail": reasons_fail,
            "warn": reasons_warn,
        },
        "sources": {
            "state_file": str(state_path),
            "dead_letter_file": str(dead_path),
            "audit_file": str(audit_path),
        },
    }

    json_out = Path(args.json_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
