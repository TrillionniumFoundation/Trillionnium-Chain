#!/usr/bin/env python3
"""PR-6 minimal anomaly alert rules for challenge treasury/forfeit operations.

Rules:
1) unresolved_challenges over threshold
2) forfeits daily increase anomaly
3) escrow stays non-zero for too long

Output:
- unified alert text for human operators
- machine-parseable key=value summary with overall status PASS/WARN/FAIL

Designed for CI/nightly integration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import math
import re
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

KV_RE = re.compile(r"(\w+)=([^\s]+)")


def to_int(raw: str | None, default: int = 0) -> int:
    if raw is None:
        return default
    s = str(raw).strip()
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return default


def parse_line(line: str) -> dict:
    kv = dict(KV_RE.findall(line))
    if not kv:
        return {}
    return {
        "event_type": kv.get("event_type", ""),
        "task_id": kv.get("task_id", ""),
        "ts_unix_ms": to_int(kv.get("ts_unix_ms"), 0),
        "block_height": to_int(kv.get("block_height"), 0),
        "challenger_delta": to_int(kv.get("challenger_delta"), 0),
        "bond_disposition": kv.get("bond_disposition", ""),
        "tx_hash": kv.get("tx_hash", ""),
    }


def load_events(path: Path) -> list[dict]:
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("[event] "):
                continue
            ev = parse_line(line)
            if ev.get("event_type") in {"challenge", "resolve"}:
                out.append(ev)
    out.sort(key=lambda e: (e["ts_unix_ms"], e["block_height"]))
    return out


def classify(value: float, warn: float, fail: float) -> str:
    if value >= fail:
        return "FAIL"
    if value >= warn:
        return "WARN"
    return "PASS"


def default_warn(fail_threshold: float) -> float:
    if fail_threshold <= 1:
        return 1
    return max(1, math.floor(fail_threshold * 0.7))


def summarize(events: list[dict], now_ms: int, window_hours: int) -> dict:
    cutoff = now_ms - window_hours * 3600 * 1000
    win_events = [e for e in events if e["ts_unix_ms"] == 0 or e["ts_unix_ms"] >= cutoff]

    open_challenges: dict[str, deque] = defaultdict(deque)
    unresolved = 0
    escrow = 0
    escrow_nonzero_since_ms: int | None = None

    forfeits_by_day: dict[str, int] = defaultdict(int)

    for e in win_events:
        et = e["event_type"]
        disp = e["bond_disposition"]
        delta = e["challenger_delta"]
        task = e["task_id"]
        ts_ms = e["ts_unix_ms"]

        if et == "challenge":
            bond = -delta if delta < 0 else 0
            open_challenges[task].append({"bond": bond, "ts_unix_ms": ts_ms})
            unresolved += 1
            escrow += max(0, bond)
            if escrow > 0 and escrow_nonzero_since_ms is None:
                escrow_nonzero_since_ms = ts_ms if ts_ms > 0 else now_ms
            continue

        # resolve
        if open_challenges[task]:
            c = open_challenges[task].popleft()
            unresolved = max(0, unresolved - 1)
            bond = int(c.get("bond", 0))
        else:
            bond = 0

        if disp == "refunded":
            escrow = max(0, escrow - bond)
        elif disp == "forfeited":
            escrow = max(0, escrow - bond)
            day = dt.datetime.fromtimestamp((ts_ms or now_ms) / 1000, tz=dt.timezone.utc).strftime("%Y-%m-%d")
            forfeits_by_day[day] += bond

        if escrow == 0:
            escrow_nonzero_since_ms = None

    now_day = dt.datetime.fromtimestamp(now_ms / 1000, tz=dt.timezone.utc)
    day0 = now_day.strftime("%Y-%m-%d")
    day1 = (now_day - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    forfeits_today = forfeits_by_day.get(day0, 0)
    forfeits_yesterday = forfeits_by_day.get(day1, 0)
    forfeits_daily_increase = forfeits_today - forfeits_yesterday

    if escrow > 0 and escrow_nonzero_since_ms is not None and escrow_nonzero_since_ms > 0:
        escrow_nonzero_hours = max(0.0, (now_ms - escrow_nonzero_since_ms) / 3600_000)
    else:
        escrow_nonzero_hours = 0.0

    return {
        "window_hours": window_hours,
        "events_in_window": len(win_events),
        "unresolved_challenges": unresolved,
        "current_escrow_balance": escrow,
        "escrow_nonzero_hours": escrow_nonzero_hours,
        "forfeits_today": forfeits_today,
        "forfeits_yesterday": forfeits_yesterday,
        "forfeits_daily_increase": forfeits_daily_increase,
        "forfeits_by_day": dict(sorted(forfeits_by_day.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="PR-6 minimal anomaly alert rules")
    ap.add_argument("--event-log", default="trillionnium/run/event-field-check.log")
    ap.add_argument("--window-hours", type=int, default=48, help="analysis window (default: 48h)")

    ap.add_argument("--fail-unresolved-challenges", type=int, default=5)
    ap.add_argument("--warn-unresolved-challenges", type=int, default=-1)

    ap.add_argument("--fail-forfeits-daily-increase", type=int, default=100)
    ap.add_argument("--warn-forfeits-daily-increase", type=int, default=-1)

    ap.add_argument("--fail-escrow-nonzero-hours", type=float, default=24.0)
    ap.add_argument("--warn-escrow-nonzero-hours", type=float, default=-1.0)

    ap.add_argument("--report", help="optional report output file")
    ap.add_argument("--ci-hard-fail-on-warn", action="store_true", help="exit 1 when overall status is WARN")
    args = ap.parse_args()

    log_path = Path(args.event_log)
    if not log_path.exists():
        print(f"status=FAIL\nalert_code=PR6_ALERT_RULES\nalert_message=event_log_missing path={log_path}")
        return 2

    warn_unresolved = args.warn_unresolved_challenges if args.warn_unresolved_challenges >= 0 else int(default_warn(args.fail_unresolved_challenges))
    warn_forfeits = args.warn_forfeits_daily_increase if args.warn_forfeits_daily_increase >= 0 else int(default_warn(args.fail_forfeits_daily_increase))
    warn_escrow_hours = args.warn_escrow_nonzero_hours if args.warn_escrow_nonzero_hours >= 0 else float(default_warn(args.fail_escrow_nonzero_hours))

    now_ms = int(time.time() * 1000)
    events = load_events(log_path)
    summary = summarize(events, now_ms=now_ms, window_hours=args.window_hours)

    s_unresolved = classify(summary["unresolved_challenges"], warn_unresolved, args.fail_unresolved_challenges)
    s_forfeits = classify(summary["forfeits_daily_increase"], warn_forfeits, args.fail_forfeits_daily_increase)
    s_escrow = classify(summary["escrow_nonzero_hours"], warn_escrow_hours, args.fail_escrow_nonzero_hours)

    statuses = [s_unresolved, s_forfeits, s_escrow]
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "WARN" in statuses:
        overall = "WARN"
    else:
        overall = "PASS"

    reasons: list[str] = []
    if s_unresolved != "PASS":
        reasons.append(f"unresolved_challenges={summary['unresolved_challenges']} threshold_warn={warn_unresolved} threshold_fail={args.fail_unresolved_challenges}")
    if s_forfeits != "PASS":
        reasons.append(f"forfeits_daily_increase={summary['forfeits_daily_increase']} threshold_warn={warn_forfeits} threshold_fail={args.fail_forfeits_daily_increase}")
    if s_escrow != "PASS":
        reasons.append(f"escrow_nonzero_hours={summary['escrow_nonzero_hours']:.2f} threshold_warn={warn_escrow_hours:.2f} threshold_fail={args.fail_escrow_nonzero_hours:.2f}")

    ts = dt.datetime.fromtimestamp(now_ms / 1000, tz=dt.timezone.utc).isoformat()
    alert_message = (
        f"[PR6][{overall}] challenge risk snapshot @ {ts} "
        f"| unresolved={summary['unresolved_challenges']} "
        f"| forfeits_daily_increase={summary['forfeits_daily_increase']} "
        f"| escrow_nonzero_hours={summary['escrow_nonzero_hours']:.2f}"
    )

    lines = [
        f"status={overall}",
        "alert_code=PR6_ALERT_RULES",
        f"alert_message={alert_message}",
        f"generated_at_utc={ts}",
        f"event_log={log_path}",
        f"window_hours={summary['window_hours']}",
        f"events_in_window={summary['events_in_window']}",
        f"rule.unresolved_challenges.status={s_unresolved}",
        f"rule.unresolved_challenges.value={summary['unresolved_challenges']}",
        f"rule.unresolved_challenges.warn_threshold={warn_unresolved}",
        f"rule.unresolved_challenges.fail_threshold={args.fail_unresolved_challenges}",
        f"rule.forfeits_daily_increase.status={s_forfeits}",
        f"rule.forfeits_daily_increase.value={summary['forfeits_daily_increase']}",
        f"rule.forfeits_daily_increase.today={summary['forfeits_today']}",
        f"rule.forfeits_daily_increase.yesterday={summary['forfeits_yesterday']}",
        f"rule.forfeits_daily_increase.warn_threshold={warn_forfeits}",
        f"rule.forfeits_daily_increase.fail_threshold={args.fail_forfeits_daily_increase}",
        f"rule.escrow_nonzero_hours.status={s_escrow}",
        f"rule.escrow_nonzero_hours.value={summary['escrow_nonzero_hours']:.2f}",
        f"rule.escrow_nonzero_hours.current_escrow_balance={summary['current_escrow_balance']}",
        f"rule.escrow_nonzero_hours.warn_threshold={warn_escrow_hours:.2f}",
        f"rule.escrow_nonzero_hours.fail_threshold={args.fail_escrow_nonzero_hours:.2f}",
    ]

    if reasons:
        lines.append("reasons=")
        lines.extend([f"- {r}" for r in reasons])

    text = "\n".join(lines) + "\n"
    print(text, end="")

    if args.report:
        rp = Path(args.report)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(text, encoding="utf-8")

    if overall == "FAIL":
        return 1
    if overall == "WARN" and args.ci_hard_fail_on_warn:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
