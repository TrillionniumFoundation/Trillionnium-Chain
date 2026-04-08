#!/usr/bin/env python3
"""Daily reconcile for challenge escrow/forfeit event-flow consistency.

Checks `challenge`/`resolve` event stream semantics:
- challenge must post bond: bond_disposition=posted, challenger_delta<0
- resolve refunded must return bond: bond_disposition=refunded, challenger_delta>0
- resolve forfeited keeps bond forfeited: bond_disposition=forfeited, challenger_delta=0

Windowing:
- --hours 24 (default), based on ts_unix_ms in event lines
- --blocks N, based on block_height (latest N blocks)

Output:
- PASS/FAIL to stdout
- concise report file for CI/nightly consumption
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Tuple

KV_RE = re.compile(r"(\w+)=([^\s]+)")


def _to_int(v: str | None, default: int = 0) -> int:
    if v is None:
        return default
    s = str(v).strip()
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return default


def parse_event_line(line: str) -> dict:
    kv = dict(KV_RE.findall(line))
    if not kv:
        return {}
    ev = {
        "event_type": kv.get("event_type", ""),
        "task_id": kv.get("task_id", ""),
        "block_height": _to_int(kv.get("block_height"), 0),
        "ts_unix_ms": _to_int(kv.get("ts_unix_ms"), 0),
        "challenger_delta": _to_int(kv.get("challenger_delta"), 0),
        "bond_disposition": kv.get("bond_disposition", ""),
        "tx_hash": kv.get("tx_hash", ""),
        "raw": line.rstrip("\n"),
    }
    return ev


def load_events(path: Path) -> List[dict]:
    events: List[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("[event] "):
                continue
            ev = parse_event_line(line)
            if ev.get("event_type") in {"challenge", "resolve"}:
                events.append(ev)
    return events


def within_window(events: List[dict], hours: int | None, blocks: int | None) -> Tuple[List[dict], str]:
    if not events:
        return [], "empty"

    if blocks is not None:
        max_h = max(e["block_height"] for e in events)
        min_h = max(0, max_h - blocks + 1)
        out = [e for e in events if e["block_height"] >= min_h]
        return out, f"last_{blocks}_blocks(h>={min_h})"

    assert hours is not None
    now_ms = int(time.time() * 1000)
    cutoff = now_ms - hours * 3600 * 1000
    out = [e for e in events if e["ts_unix_ms"] >= cutoff]
    ts = dt.datetime.fromtimestamp(cutoff / 1000, tz=dt.timezone.utc).isoformat()
    return out, f"last_{hours}h(ts>={ts})"


def reconcile(events: List[dict], strict_window: bool) -> Tuple[bool, dict]:
    open_challenges: Dict[str, deque] = defaultdict(deque)
    details: List[str] = []

    posted_total = 0
    refunded_total = 0
    forfeited_total = 0
    cnt_challenge = 0
    cnt_resolve = 0
    carry_in_resolve = 0

    for ev in events:
        et = ev["event_type"]
        task_id = ev["task_id"]
        disp = ev["bond_disposition"]
        delta = ev["challenger_delta"]
        tx = ev["tx_hash"]

        if et == "challenge":
            cnt_challenge += 1
            if disp != "posted":
                details.append(
                    f"challenge bad disposition task={task_id} tx={tx} got={disp} want=posted"
                )
            if delta >= 0:
                details.append(
                    f"challenge bad challenger_delta task={task_id} tx={tx} got={delta} want<0"
                )
                bond = 0
            else:
                bond = -delta
                posted_total += bond
            open_challenges[task_id].append({"bond": bond, "tx": tx})
            continue

        # resolve
        cnt_resolve += 1
        if disp not in {"refunded", "forfeited"}:
            details.append(
                f"resolve unknown disposition task={task_id} tx={tx} got={disp} want=refunded|forfeited"
            )
            continue

        if not open_challenges[task_id]:
            carry_in_resolve += 1
            if strict_window:
                details.append(
                    f"resolve without in-window challenge task={task_id} tx={tx} disposition={disp}"
                )
            # still validate local semantics
            if disp == "refunded" and delta <= 0:
                details.append(
                    f"resolve refunded bad challenger_delta task={task_id} tx={tx} got={delta} want>0"
                )
            if disp == "forfeited" and delta != 0:
                details.append(
                    f"resolve forfeited bad challenger_delta task={task_id} tx={tx} got={delta} want=0"
                )
            continue

        ch = open_challenges[task_id].popleft()
        bond = int(ch["bond"])

        if disp == "refunded":
            if delta <= 0:
                details.append(
                    f"resolve refunded bad challenger_delta task={task_id} tx={tx} got={delta} want>0"
                )
            if bond > 0 and delta != bond:
                details.append(
                    f"refund mismatch task={task_id} challenge_tx={ch['tx']} resolve_tx={tx} bond={bond} refund={delta}"
                )
            refunded_total += max(0, delta)
        else:  # forfeited
            if delta != 0:
                details.append(
                    f"resolve forfeited bad challenger_delta task={task_id} tx={tx} got={delta} want=0"
                )
            forfeited_total += max(0, bond)

    carry_out_open = sum(len(q) for q in open_challenges.values())
    if strict_window and carry_out_open > 0:
        details.append(f"in-window unresolved challenges={carry_out_open}")

    ok = len(details) == 0
    return ok, {
        "challenge_count": cnt_challenge,
        "resolve_count": cnt_resolve,
        "posted_total": posted_total,
        "refunded_total": refunded_total,
        "forfeited_total": forfeited_total,
        "carry_in_resolve": carry_in_resolve,
        "carry_out_open": carry_out_open,
        "details": details,
    }


def write_report(path: Path, status: str, window_desc: str, event_log: Path, summary: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now().astimezone().isoformat()
    lines = [
        f"status={status}",
        f"generated_at={now}",
        f"window={window_desc}",
        f"event_log={event_log}",
        f"challenge_count={summary['challenge_count']}",
        f"resolve_count={summary['resolve_count']}",
        f"posted_total={summary['posted_total']}",
        f"refunded_total={summary['refunded_total']}",
        f"forfeited_total={summary['forfeited_total']}",
        f"carry_in_resolve={summary['carry_in_resolve']}",
        f"carry_out_open={summary['carry_out_open']}",
    ]

    if summary["details"]:
        lines.append("details=")
        for d in summary["details"][:50]:
            lines.append(f"- {d}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Reconcile challenge escrow/forfeit against event flow")
    ap.add_argument("--event-log", default="trillionnium/run/event-field-check.log", help="node event log file")
    w = ap.add_mutually_exclusive_group()
    w.add_argument("--hours", type=int, default=24, help="time window in hours (default: 24)")
    w.add_argument("--blocks", type=int, help="latest N blocks window")
    ap.add_argument("--strict-window", action="store_true", help="treat window carry-in/out as FAIL")
    ap.add_argument("--report", help="report output path")
    args = ap.parse_args()

    event_log = Path(args.event_log)
    if not event_log.exists():
        print(f"FAIL missing event log: {event_log}", file=sys.stderr)
        return 2

    all_events = load_events(event_log)
    win_events, window_desc = within_window(all_events, args.hours if args.blocks is None else None, args.blocks)

    ok, summary = reconcile(win_events, strict_window=args.strict_window)
    status = "PASS" if ok else "FAIL"

    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = Path(args.report) if args.report else Path(f"run/reconcile/challenge-fundflow-{ts}.report.txt")
    write_report(report_path, status, window_desc, event_log, summary)

    print(
        f"{status} challenge_fundflow_reconcile window={window_desc} "
        f"challenges={summary['challenge_count']} resolves={summary['resolve_count']} "
        f"posted={summary['posted_total']} refunded={summary['refunded_total']} forfeited={summary['forfeited_total']} "
        f"details={len(summary['details'])} report={report_path}"
    )

    if summary["details"]:
        for d in summary["details"][:10]:
            print(f"  - {d}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
