#!/usr/bin/env python3
"""P11: Notification SLO report (24h / 7d) for PR7 delivery pipeline.

Outputs:
- run/pr11/notification-slo.md
- run/pr11/notification-slo.json

Metrics per window:
- sent_rate
- suppressed_rate
- failed_rate
- p95_delivery_attempts
- channel_split (imessage/slack/telegram)

Data sources (best effort):
- run/pr7-alert-delivery/audit.jsonl        (preferred for time-window metrics)
- run/pr7-alert-delivery/dead-letter.jsonl  (failed events supplement)
- run/pr7-alert-delivery/state.json         (cumulative fallback)

When source data is insufficient for strict window slicing, report degrades gracefully
with explicit notes and fallback values.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
from pathlib import Path
from typing import Any

CHANNELS = ["imessage", "slack", "telegram"]


def parse_iso_utc(raw: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except Exception:
        return None


def safe_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def pct(numer: int, denom: int) -> float:
    if denom <= 0:
        return 0.0
    return numer * 100.0 / denom


def percentile_p95(values: list[int]) -> float | None:
    if not values:
        return None
    vals = sorted(values)
    # nearest-rank method
    rank = math.ceil(0.95 * len(vals))
    idx = max(0, min(len(vals) - 1, rank - 1))
    return float(vals[idx])


def build_window_metrics(
    *,
    window_name: str,
    now_utc: dt.datetime,
    hours: int,
    audit_rows: list[dict[str, Any]],
    dead_rows: list[dict[str, Any]],
    state_stats: dict[str, Any],
) -> dict[str, Any]:
    cutoff = now_utc - dt.timedelta(hours=hours)

    # Preferred observed events from audit.jsonl
    audit_in: list[dict[str, Any]] = []
    for r in audit_rows:
        t = parse_iso_utc(str(r.get("at_utc", "")))
        if t is not None and t >= cutoff:
            audit_in.append(r)

    # dead-letter supplements failed events; use only rows in window
    dead_in: list[dict[str, Any]] = []
    for r in dead_rows:
        t = parse_iso_utc(str(r.get("created_at_utc", "")))
        if t is not None and t >= cutoff:
            dead_in.append(r)

    notes: list[str] = []
    degraded = False

    sent = sum(1 for r in audit_in if bool(r.get("ok", False)))
    # In audit rows, failed sends have ok=false; dead-letter is terminal failure record.
    # We count dead-letter as canonical failed events to avoid overcounting per-channel failures.
    failed = len(dead_in)

    # Suppressed events are not currently written to jsonl; they exist only in state cumulative counters.
    suppressed_window_observable = 0
    total_observed = sent + failed + suppressed_window_observable

    # fallback from cumulative state when window has no auditable events
    state_sent = int(state_stats.get("alerts_sent", 0) or 0)
    state_suppressed = int(state_stats.get("alerts_suppressed", 0) or 0)
    state_failed = int(state_stats.get("alerts_failed", 0) or 0)
    state_total = max(0, state_sent + state_suppressed + state_failed)

    used_fallback = False
    if total_observed == 0 and state_total > 0:
        used_fallback = True
        degraded = True
        notes.append(
            f"{window_name}: no timestamped events in window; fallback to cumulative state counters (non-windowed)."
        )
        sent = state_sent
        failed = state_failed
        suppressed_window_observable = state_suppressed
        total_observed = state_total

    if total_observed == 0:
        degraded = True
        notes.append(f"{window_name}: insufficient data; no events found in window and no cumulative counters available.")

    sent_rate = pct(sent, total_observed)
    suppressed_rate = pct(suppressed_window_observable, total_observed)
    failed_rate = pct(failed, total_observed)

    attempts = []
    for r in audit_in:
        try:
            attempts.append(int(r.get("attempts", 0) or 0))
        except Exception:
            continue
    p95_attempts = percentile_p95(attempts)
    if p95_attempts is None and used_fallback:
        degraded = True
        notes.append(f"{window_name}: p95_delivery_attempts unavailable in fallback mode (audit window empty).")
    elif p95_attempts is None:
        degraded = True
        notes.append(f"{window_name}: p95_delivery_attempts unavailable (no audit attempts in window).")

    split_counts = {c: 0 for c in CHANNELS}
    for r in audit_in:
        if not bool(r.get("ok", False)):
            continue
        ch = str(r.get("channel", "")).strip().lower()
        if ch in split_counts:
            split_counts[ch] += 1

    split_total = sum(split_counts.values())
    channel_split = {
        c: {
            "count": split_counts[c],
            "rate_pct": round(pct(split_counts[c], split_total), 4) if split_total > 0 else 0.0,
        }
        for c in CHANNELS
    }
    if split_total == 0:
        degraded = True
        notes.append(f"{window_name}: channel_split unavailable (no successful audit rows in window).")

    return {
        "window": window_name,
        "hours": hours,
        "range": {
            "from_utc": cutoff.isoformat().replace("+00:00", "Z"),
            "to_utc": now_utc.isoformat().replace("+00:00", "Z"),
        },
        "counts": {
            "total": int(total_observed),
            "sent": int(sent),
            "suppressed": int(suppressed_window_observable),
            "failed": int(failed),
        },
        "metrics": {
            "sent_rate": round(sent_rate, 4),
            "suppressed_rate": round(suppressed_rate, 4),
            "failed_rate": round(failed_rate, 4),
            "p95_delivery_attempts": p95_attempts,
            "channel_split": channel_split,
        },
        "source_counts": {
            "audit_rows_in_window": len(audit_in),
            "dead_letters_in_window": len(dead_in),
        },
        "degraded": degraded,
        "notes": notes,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate P11 notification SLO report (24h/7d)")
    ap.add_argument("--audit-file", default="run/pr7-alert-delivery/audit.jsonl")
    ap.add_argument("--dead-letter-file", default="run/pr7-alert-delivery/dead-letter.jsonl")
    ap.add_argument("--state-file", default="run/pr7-alert-delivery/state.json")
    ap.add_argument("--out", default="run/pr11/notification-slo.md")
    ap.add_argument("--json-out", default="run/pr11/notification-slo.json")
    args = ap.parse_args()

    root = Path.cwd()
    audit_path = root / args.audit_file
    dead_path = root / args.dead_letter_file
    state_path = root / args.state_file
    out_md = root / args.out
    out_json = root / args.json_out

    now_utc = dt.datetime.now(dt.timezone.utc)
    generated_at = now_utc.isoformat().replace("+00:00", "Z")

    audit_rows = read_jsonl(audit_path)
    dead_rows = read_jsonl(dead_path)
    state = safe_json(state_path)
    state_stats = state.get("stats", {}) if isinstance(state.get("stats", {}), dict) else {}

    windows = [
        build_window_metrics(
            window_name="24h",
            now_utc=now_utc,
            hours=24,
            audit_rows=audit_rows,
            dead_rows=dead_rows,
            state_stats=state_stats,
        ),
        build_window_metrics(
            window_name="7d",
            now_utc=now_utc,
            hours=24 * 7,
            audit_rows=audit_rows,
            dead_rows=dead_rows,
            state_stats=state_stats,
        ),
    ]

    payload: dict[str, Any] = {
        "generated_at_utc": generated_at,
        "sources": {
            "audit_file": str(audit_path) if audit_path.exists() else None,
            "dead_letter_file": str(dead_path) if dead_path.exists() else None,
            "state_file": str(state_path) if state_path.exists() else None,
        },
        "windows": windows,
        "degraded": any(bool(w.get("degraded", False)) for w in windows),
    }

    lines: list[str] = []
    lines.append("# P11 Notification SLO Report")
    lines.append("")
    lines.append(f"- generated_at_utc: `{generated_at}`")
    lines.append(f"- source.audit: `{audit_path if audit_path.exists() else 'MISSING'}`")
    lines.append(f"- source.dead_letter: `{dead_path if dead_path.exists() else 'MISSING'}`")
    lines.append(f"- source.state: `{state_path if state_path.exists() else 'MISSING'}`")
    lines.append("")

    for w in windows:
        name = w["window"]
        metrics = w["metrics"]
        counts = w["counts"]
        lines.append(f"## Window: {name}")
        lines.append(f"- range_utc: `{w['range']['from_utc']}` -> `{w['range']['to_utc']}`")
        lines.append(
            f"- counts: total=`{counts['total']}`, sent=`{counts['sent']}`, suppressed=`{counts['suppressed']}`, failed=`{counts['failed']}`"
        )
        lines.append(f"- sent_rate: `{metrics['sent_rate']:.2f}%`")
        lines.append(f"- suppressed_rate: `{metrics['suppressed_rate']:.2f}%`")
        lines.append(f"- failed_rate: `{metrics['failed_rate']:.2f}%`")
        p95 = metrics.get("p95_delivery_attempts")
        lines.append(f"- p95_delivery_attempts: `{p95 if p95 is not None else 'n/a'}`")
        lines.append("- channel_split:")
        for ch in CHANNELS:
            info = metrics["channel_split"].get(ch, {"count": 0, "rate_pct": 0.0})
            lines.append(f"  - {ch}: count=`{info['count']}`, rate=`{info['rate_pct']:.2f}%`")
        lines.append(
            f"- source_rows: audit_in_window=`{w['source_counts']['audit_rows_in_window']}`, dead_letters_in_window=`{w['source_counts']['dead_letters_in_window']}`"
        )
        if w.get("degraded", False):
            lines.append("- degraded: `true`")
            for n in w.get("notes", []):
                lines.append(f"  - note: {n}")
        else:
            lines.append("- degraded: `false`")
        lines.append("")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"[OK] wrote {out_md}")
    print(f"[OK] wrote {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
