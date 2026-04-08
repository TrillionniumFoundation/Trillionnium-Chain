#!/usr/bin/env python3
"""Generate PR-7 TopN anomaly summary in markdown.

Focus areas:
1) unresolved challenge tasks
2) forfeit spikes by day
3) escrow lingering tasks

Inputs are best-effort and can be missing; summary still renders with hints.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
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


def ts_to_utc(ts_ms: int | None) -> str:
    if not ts_ms or ts_ms <= 0:
        return "n/a"
    return dt.datetime.fromtimestamp(ts_ms / 1000, tz=dt.timezone.utc).isoformat()


def parse_event_line(line: str) -> dict[str, str]:
    return dict(KV_RE.findall(line))


def load_events(event_log: Path) -> list[dict]:
    events: list[dict] = []
    if not event_log.exists():
        return events
    with event_log.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.startswith("[event] "):
                continue
            kv = parse_event_line(line)
            et = kv.get("event_type", "")
            if et not in {"challenge", "resolve"}:
                continue
            events.append(
                {
                    "event_type": et,
                    "task_id": kv.get("task_id", ""),
                    "bond_disposition": kv.get("bond_disposition", ""),
                    "challenger_delta": to_int(kv.get("challenger_delta"), 0),
                    "ts_unix_ms": to_int(kv.get("ts_unix_ms"), 0),
                    "block_height": to_int(kv.get("block_height"), 0),
                }
            )
    events.sort(key=lambda e: (e["ts_unix_ms"], e["block_height"]))
    return events


def load_pr5(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def analyze(events: list[dict], now_ms: int) -> tuple[list[dict], list[dict], list[dict], dict[str, int]]:
    # unresolved/escrow tracking per task
    open_challenges: dict[str, deque] = defaultdict(deque)
    unresolved_count: dict[str, int] = defaultdict(int)
    unresolved_bond: dict[str, int] = defaultdict(int)
    first_open_ts: dict[str, int] = {}

    forfeits_by_day: dict[str, int] = defaultdict(int)
    forfeits_events_by_day: dict[str, int] = defaultdict(int)

    for e in events:
        task = e["task_id"] or "unknown"
        et = e["event_type"]
        ts_ms = e["ts_unix_ms"] or now_ms

        if et == "challenge":
            bond = max(0, -int(e.get("challenger_delta", 0)))
            open_challenges[task].append({"bond": bond, "ts_unix_ms": ts_ms})
            unresolved_count[task] += 1
            unresolved_bond[task] += bond
            if task not in first_open_ts:
                first_open_ts[task] = ts_ms
            continue

        # resolve: settle one open challenge if present
        settled_bond = 0
        if open_challenges[task]:
            c = open_challenges[task].popleft()
            settled_bond = int(c.get("bond", 0))
            unresolved_count[task] = max(0, unresolved_count[task] - 1)
            unresolved_bond[task] = max(0, unresolved_bond[task] - settled_bond)
            if unresolved_count[task] == 0:
                first_open_ts.pop(task, None)

        if e.get("bond_disposition") == "forfeited":
            day = dt.datetime.fromtimestamp(ts_ms / 1000, tz=dt.timezone.utc).strftime("%Y-%m-%d")
            forfeits_by_day[day] += max(0, settled_bond)
            forfeits_events_by_day[day] += 1

    unresolved_top = [
        {
            "task_id": task,
            "open_challenges": cnt,
            "open_bond": unresolved_bond.get(task, 0),
            "first_open_ts": first_open_ts.get(task, 0),
        }
        for task, cnt in unresolved_count.items()
        if cnt > 0
    ]
    unresolved_top.sort(key=lambda x: (x["open_challenges"], x["open_bond"], x["first_open_ts"]), reverse=True)

    escrow_lingering_top = []
    for item in unresolved_top:
        first_ts = item.get("first_open_ts", 0)
        hrs = 0.0 if first_ts <= 0 else max(0.0, (now_ms - first_ts) / 3600_000)
        escrow_lingering_top.append(
            {
                "task_id": item["task_id"],
                "lingering_hours": hrs,
                "open_bond": item["open_bond"],
                "open_challenges": item["open_challenges"],
                "first_open_ts": first_ts,
            }
        )
    escrow_lingering_top.sort(key=lambda x: (x["lingering_hours"], x["open_bond"], x["open_challenges"]), reverse=True)

    forfeit_spikes_top = [
        {
            "day_utc": day,
            "forfeit_bond": amt,
            "forfeit_events": forfeits_events_by_day.get(day, 0),
        }
        for day, amt in forfeits_by_day.items()
    ]
    forfeit_spikes_top.sort(key=lambda x: (x["forfeit_bond"], x["forfeit_events"], x["day_utc"]), reverse=True)

    totals = {
        "unresolved_tasks": len(unresolved_top),
        "unresolved_open_challenges": sum(i["open_challenges"] for i in unresolved_top),
        "unresolved_open_bond": sum(i["open_bond"] for i in unresolved_top),
        "forfeit_days": len(forfeit_spikes_top),
        "forfeit_bond_total": sum(i["forfeit_bond"] for i in forfeit_spikes_top),
        "forfeit_events_total": sum(i["forfeit_events"] for i in forfeit_spikes_top),
    }
    return unresolved_top, forfeit_spikes_top, escrow_lingering_top, totals


def render_markdown(
    top_n: int,
    out_path: Path,
    event_log: Path,
    pr5_json: Path,
    unresolved_top: list[dict],
    forfeit_spikes_top: list[dict],
    escrow_lingering_top: list[dict],
    totals: dict[str, int],
    pr5: dict,
) -> str:
    now = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    pr5_status = pr5.get("status", "MISSING") if pr5 else "MISSING"

    lines: list[str] = []
    lines.append("# PR-7 TopN Anomaly Summary")
    lines.append("")
    lines.append(f"- generated_at_utc: `{now}`")
    lines.append(f"- top_n: `{top_n}`")
    lines.append(f"- source.event_log: `{event_log}`")
    lines.append(f"- source.pr5_reconcile_json: `{pr5_json if pr5_json.exists() else 'MISSING'}`")
    lines.append(f"- pr5.reconcile.status: `{pr5_status}`")
    lines.append("")

    lines.append("## Snapshot")
    lines.append(f"- unresolved.tasks: `{totals['unresolved_tasks']}`")
    lines.append(f"- unresolved.open_challenges: `{totals['unresolved_open_challenges']}`")
    lines.append(f"- unresolved.open_bond: `{totals['unresolved_open_bond']}`")
    lines.append(f"- forfeit.days: `{totals['forfeit_days']}`")
    lines.append(f"- forfeit.events.total: `{totals['forfeit_events_total']}`")
    lines.append(f"- forfeit.bond.total: `{totals['forfeit_bond_total']}`")
    lines.append("")

    lines.append("## TopN Unresolved Tasks")
    if unresolved_top:
        for i, item in enumerate(unresolved_top[:top_n], 1):
            lines.append(
                f"{i}. task_id=`{item['task_id']}` | open_challenges=`{item['open_challenges']}` | open_bond=`{item['open_bond']}` | first_open_utc=`{ts_to_utc(item['first_open_ts'])}`"
            )
    else:
        lines.append("- ✅ no unresolved task found in current event window")
    lines.append("")

    lines.append("## TopN Forfeit Spikes (by UTC day)")
    if forfeit_spikes_top:
        for i, item in enumerate(forfeit_spikes_top[:top_n], 1):
            lines.append(
                f"{i}. day_utc=`{item['day_utc']}` | forfeit_bond=`{item['forfeit_bond']}` | forfeit_events=`{item['forfeit_events']}`"
            )
    else:
        lines.append("- ✅ no forfeit spike found in current event window")
    lines.append("")

    lines.append("## TopN Escrow Lingering")
    if escrow_lingering_top:
        for i, item in enumerate(escrow_lingering_top[:top_n], 1):
            lines.append(
                f"{i}. task_id=`{item['task_id']}` | lingering_hours=`{item['lingering_hours']:.2f}` | open_bond=`{item['open_bond']}` | open_challenges=`{item['open_challenges']}` | first_open_utc=`{ts_to_utc(item['first_open_ts'])}`"
            )
    else:
        lines.append("- ✅ no lingering escrow found in current event window")
    lines.append("")

    lines.append("## Triage Hint")
    lines.append("- unresolved/lingering: 回查 `query-events --task-id <TASK_ID> --limit 100`")
    lines.append("- forfeit spikes: 联动 `run/pr5-reconcile/*/summary.txt` 与 `reconcile.json` 做日增对账")

    text = "\n".join(lines) + "\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PR-7 TopN anomaly markdown summary")
    ap.add_argument("--event-log", default="trillionnium/run/event-field-check.log")
    ap.add_argument("--pr5-reconcile-json", default="run/pr5-reconcile/latest/reconcile.json")
    ap.add_argument("--out", default="run/pr6-ops/topn-anomaly-summary.md")
    ap.add_argument("--top-n", type=int, default=5)
    args = ap.parse_args()

    event_log = Path(args.event_log)
    pr5_json = Path(args.pr5_reconcile_json)
    out = Path(args.out)

    events = load_events(event_log)
    pr5 = load_pr5(pr5_json)
    now_ms = int(dt.datetime.now(tz=dt.timezone.utc).timestamp() * 1000)

    unresolved_top, forfeit_spikes_top, escrow_lingering_top, totals = analyze(events, now_ms=now_ms)
    render_markdown(
        top_n=max(1, args.top_n),
        out_path=out,
        event_log=event_log,
        pr5_json=pr5_json,
        unresolved_top=unresolved_top,
        forfeit_spikes_top=forfeit_spikes_top,
        escrow_lingering_top=escrow_lingering_top,
        totals=totals,
        pr5=pr5,
    )
    print(f"[OK] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
