#!/usr/bin/env python3
"""PR9: generate weekly alert governance report (markdown + json).

Data sources (best effort):
- run/pr7-alert-delivery/state.json / dead-letter.jsonl
- run/pr7-topn/*/topn-anomaly-summary.md
- run/pr7-threshold-advisor/*/threshold-advice.json
- run/pr9/alert-thresholds.env and run/pr9/alert-thresholds.previous.env
- run/pr9/history/weekly-alert-governance-*.json (for week-over-week diff)

Outputs:
- run/pr9/weekly-alert-governance.md
- run/pr9/weekly-alert-governance.json
- run/pr9/history/weekly-alert-governance-YYYYMMDDTHHMMSSZ.json (snapshot)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ENV_RE = re.compile(r"^([A-Z0-9_]+)=(.*)$")


def safe_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def safe_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ENV_RE.match(line)
        if not m:
            continue
        out[m.group(1)] = m.group(2)
    return out


def latest_file(pattern: str) -> Path | None:
    matches = sorted(Path.cwd().glob(pattern))
    return matches[-1] if matches else None


def rows_within_lookback(
    path: Path,
    lookback_days: int,
    *,
    timestamp_field: str,
    now_dt: dt.datetime | None = None,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if now_dt is None:
        now_dt = dt.datetime.now(dt.timezone.utc)
    cutoff = now_dt - dt.timedelta(days=max(1, lookback_days))
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        ts = obj.get(timestamp_field, "")
        in_window = False
        if isinstance(ts, str) and ts:
            try:
                t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if t.tzinfo is not None:
                    in_window = cutoff <= t <= now_dt
            except Exception:
                in_window = False
        if in_window:
            rows.append(obj)
    return rows


def read_dead_letters(path: Path, lookback_days: int, now_dt: dt.datetime | None = None) -> list[dict[str, Any]]:
    return rows_within_lookback(path, lookback_days, timestamp_field="created_at_utc", now_dt=now_dt)


def read_delivery_summaries(path: Path, lookback_days: int, now_dt: dt.datetime | None = None) -> list[dict[str, Any]]:
    rows = rows_within_lookback(path, lookback_days, timestamp_field="at_utc", now_dt=now_dt)
    return [row for row in rows if row.get("record_type") == "delivery_summary"]


def extract_topn_sections(md_path: Path) -> dict[str, list[str]]:
    sections = {
        "unresolved": [],
        "forfeit": [],
        "escrow": [],
    }
    if not md_path.exists():
        return sections

    mode = ""
    for raw in md_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.rstrip()
        if line.startswith("## TopN Unresolved Tasks"):
            mode = "unresolved"
            continue
        if line.startswith("## TopN Forfeit Spikes"):
            mode = "forfeit"
            continue
        if line.startswith("## TopN Escrow Lingering"):
            mode = "escrow"
            continue
        if line.startswith("## "):
            mode = ""
            continue
        if mode and line.strip() and (line.lstrip().startswith("-") or line.lstrip()[0:1].isdigit()):
            sections[mode].append(clean_topn_line(line))
    return sections


def clean_topn_line(line: str) -> str:
    cleaned = line.strip()
    cleaned = re.sub(r"^\d+\.\s*", "", cleaned)
    cleaned = re.sub(r"^-\s*", "", cleaned)
    return cleaned


def pct(numer: int, denom: int) -> float:
    return (numer / denom * 100.0) if denom > 0 else 0.0


def non_negative_int(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def pct_or_none(numer: int, denom: int) -> float | None:
    if denom <= 0:
        return None
    return numer / denom * 100.0


def pct_delta(curr: float, prev: float) -> float:
    return curr - prev


def delta(curr: int | float, prev: int | float) -> int | float:
    return curr - prev


def fmt_delta(v: int | float, unit: str = "") -> str:
    if isinstance(v, float):
        sign = "+" if v >= 0 else ""
        return f"{sign}{v:.2f}{unit}"
    sign = "+" if v >= 0 else ""
    return f"{sign}{v}{unit}"


def fmt_pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}%"


def index_map(rows: list[str]) -> dict[str, int]:
    return {clean_topn_line(r): i + 1 for i, r in enumerate(rows)}


def topn_diff(curr: list[str], prev: list[str]) -> dict[str, Any]:
    c_map = index_map(curr)
    p_map = index_map(prev)
    c_keys = set(c_map)
    p_keys = set(p_map)
    entered = sorted(c_keys - p_keys)
    exited = sorted(p_keys - c_keys)
    rank_shift = []
    for k in sorted(c_keys & p_keys):
        move = p_map[k] - c_map[k]
        if move != 0:
            rank_shift.append(
                {
                    "item": k,
                    "from": p_map[k],
                    "to": c_map[k],
                    "delta_rank": move,
                }
            )
    return {
        "entered": entered,
        "exited": exited,
        "rank_shift": rank_shift,
    }


def snapshot_timestamp(path: Path) -> dt.datetime | None:
    m = re.match(r"weekly-alert-governance-(\d{8}T\d{6}Z)\.json$", path.name)
    if not m:
        return None
    try:
        return dt.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def payload_history_fingerprint(payload: dict[str, Any]) -> str:
    stable_payload = dict(payload)
    stable_payload.pop("generated_at_utc", None)
    encoded = json.dumps(stable_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def find_previous_week_json(history_dir: Path, current_json_out: Path, now_dt: dt.datetime, lookback_days: int) -> Path | None:
    if not history_dir.exists():
        return None
    target_cutoff = now_dt - dt.timedelta(days=max(1, lookback_days))
    min_age = dt.timedelta(days=max(1, lookback_days) // 2)
    candidates: list[tuple[float, Path]] = []
    fallback_candidates: list[tuple[float, Path]] = []
    for p in sorted(history_dir.glob("weekly-alert-governance-*.json")):
        if p.resolve() == current_json_out.resolve():
            continue
        ts = snapshot_timestamp(p)
        if ts is None or ts > now_dt:
            continue
        distance = abs((ts - target_cutoff).total_seconds())
        fallback_candidates.append((distance, p))
        if now_dt - ts >= min_age:
            candidates.append((distance, p))
    if not candidates:
        candidates = fallback_candidates
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1].name))
    return candidates[0][1]


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PR9 weekly alert governance markdown+json")
    ap.add_argument("--lookback-days", type=int, default=7)
    ap.add_argument("--top-n", type=int, default=5)
    ap.add_argument("--out", default="run/pr9/weekly-alert-governance.md")
    ap.add_argument("--json-out", default="run/pr9/weekly-alert-governance.json")
    ap.add_argument("--history-dir", default="run/pr9/history")
    args = ap.parse_args()

    if args.lookback_days < 1:
        ap.error("--lookback-days must be >= 1")
    if args.top_n < 1:
        ap.error("--top-n must be >= 1")

    root = Path.cwd()
    out_md = root / args.out
    out_json = root / args.json_out
    history_dir = root / args.history_dir
    now_dt = dt.datetime.now(dt.timezone.utc)

    state_path = root / "run/pr7-alert-delivery/state.json"
    dead_letter_path = root / "run/pr7-alert-delivery/dead-letter.jsonl"
    latest_topn = latest_file("run/pr7-topn/*/topn-anomaly-summary.md")
    latest_advice = latest_file("run/pr7-threshold-advisor/*/threshold-advice.json")
    env_now_path = root / "run/pr9/alert-thresholds.env"
    env_prev_path = root / "run/pr9/alert-thresholds.previous.env"

    state = safe_json(state_path)
    stats = state.get("stats", {}) if isinstance(state.get("stats", {}), dict) else {}
    sent = non_negative_int(stats.get("alerts_sent", 0))
    suppressed = non_negative_int(stats.get("alerts_suppressed", 0))
    failed = non_negative_int(stats.get("alerts_failed", 0))
    total = max(0, sent + suppressed + failed)

    audit_path = root / "run/pr7-alert-delivery/audit.jsonl"
    delivery_summaries = read_delivery_summaries(audit_path, args.lookback_days, now_dt=now_dt)
    partial_success_count = sum(1 for row in delivery_summaries if row.get("event") == "partial_success")
    channels_ok_total = sum(non_negative_int(row.get("channels_ok", 0)) for row in delivery_summaries)
    channels_failed_total = sum(non_negative_int(row.get("channels_failed", 0)) for row in delivery_summaries)
    delivery_routes_total = channels_ok_total + channels_failed_total
    partial_success_rate = pct(partial_success_count, len(delivery_summaries))
    channel_delivery_success_rate = pct(channels_ok_total, delivery_routes_total)

    suppression_rate = pct(suppressed, total)
    failure_rate = pct(failed, total)
    delivery_attempted = max(0, sent + failed)
    delivery_success_rate = pct_or_none(sent, delivery_attempted)
    suppression_share_pct = pct(suppressed, total)

    dead_letters = read_dead_letters(dead_letter_path, lookback_days=args.lookback_days, now_dt=now_dt)
    dead_letters_week = len(dead_letters)

    sections_raw = extract_topn_sections(latest_topn) if latest_topn else {"unresolved": [], "forfeit": [], "escrow": []}
    sections = {
        "unresolved": [clean_topn_line(x) for x in sections_raw.get("unresolved", [])][: max(1, args.top_n)],
        "forfeit": [clean_topn_line(x) for x in sections_raw.get("forfeit", [])][: max(1, args.top_n)],
        "escrow": [clean_topn_line(x) for x in sections_raw.get("escrow", [])][: max(1, args.top_n)],
    }

    advice = safe_json(latest_advice) if latest_advice else {}
    sug = advice.get("suggestions", {}) if isinstance(advice.get("suggestions", {}), dict) else {}

    env_now = parse_env(env_now_path)
    env_prev = parse_env(env_prev_path)
    changed_keys: list[dict[str, str]] = []
    for k in sorted(set(env_now.keys()) | set(env_prev.keys())):
        if env_now.get(k) != env_prev.get(k):
            changed_keys.append({"key": k, "old": env_prev.get(k, "(missing)"), "new": env_now.get(k, "(missing)")})

    # Week-over-week baseline from history json.
    prev_week_json_path = find_previous_week_json(history_dir, out_json, now_dt, args.lookback_days)
    prev_week = safe_json(prev_week_json_path) if prev_week_json_path else {}
    prev_metrics = prev_week.get("metrics", {}) if isinstance(prev_week.get("metrics", {}), dict) else {}
    prev_topn = prev_week.get("topn", {}) if isinstance(prev_week.get("topn", {}), dict) else {}
    prev_threshold_changes = prev_week.get("threshold", {}).get("changed_keys", []) if isinstance(prev_week.get("threshold", {}), dict) else []
    prev_threshold_keys = {x.get("key") for x in prev_threshold_changes if isinstance(x, dict) and x.get("key")}

    has_prev = bool(prev_week_json_path and prev_metrics)
    prev_total = int(prev_metrics.get("alerts_total", 0) or 0) if has_prev else 0
    prev_suppression_rate = float(prev_metrics.get("suppression_rate_pct", 0.0) or 0.0) if has_prev else 0.0
    prev_failure_rate = float(prev_metrics.get("failure_rate_pct", 0.0) or 0.0) if has_prev else 0.0
    prev_delivery_success_rate = (
        float(prev_metrics.get("delivery_success_rate_pct", 0.0) or 0.0)
        if has_prev and prev_metrics.get("delivery_success_rate_pct") is not None
        else None
    )
    prev_suppression_share_pct = float(prev_metrics.get("suppression_share_pct", 0.0) or 0.0) if has_prev else 0.0

    wow = {
        "available": has_prev,
        "baseline_json": str(prev_week_json_path) if prev_week_json_path else None,
        "alerts_total_delta": delta(total, prev_total) if has_prev else None,
        "suppression_rate_pct_delta": pct_delta(suppression_rate, prev_suppression_rate) if has_prev else None,
        "failure_rate_pct_delta": pct_delta(failure_rate, prev_failure_rate) if has_prev else None,
        "delivery_success_rate_pct_delta": (
            pct_delta(delivery_success_rate, prev_delivery_success_rate)
            if has_prev and delivery_success_rate is not None and prev_delivery_success_rate is not None
            else None
        ),
        "suppression_share_pct_delta": pct_delta(suppression_share_pct, prev_suppression_share_pct) if has_prev else None,
        "topn": {
            "unresolved": topn_diff(sections["unresolved"], prev_topn.get("unresolved", []) if isinstance(prev_topn.get("unresolved", []), list) else []) if has_prev else {"entered": [], "exited": [], "rank_shift": []},
            "forfeit": topn_diff(sections["forfeit"], prev_topn.get("forfeit", []) if isinstance(prev_topn.get("forfeit", []), list) else []) if has_prev else {"entered": [], "exited": [], "rank_shift": []},
            "escrow": topn_diff(sections["escrow"], prev_topn.get("escrow", []) if isinstance(prev_topn.get("escrow", []), list) else []) if has_prev else {"entered": [], "exited": [], "rank_shift": []},
        },
        "threshold_changed_keys_delta": (len(changed_keys) - len(prev_threshold_keys)) if has_prev else None,
        "threshold_new_keys_vs_last_week": sorted({x["key"] for x in changed_keys} - prev_threshold_keys) if has_prev else [],
        "threshold_removed_keys_vs_last_week": sorted(prev_threshold_keys - {x["key"] for x in changed_keys}) if has_prev else [],
    }

    now_utc = now_dt.strftime("%Y-%m-%d %H:%M:%SZ")

    payload: dict[str, Any] = {
        "generated_at_utc": now_utc,
        "lookback_days": args.lookback_days,
        "sources": {
            "pr7_delivery_state": str(state_path) if state_path.exists() else None,
            "pr7_dead_letter": str(dead_letter_path) if dead_letter_path.exists() else None,
            "pr7_delivery_audit": str(audit_path) if audit_path.exists() else None,
            "pr7_topn_latest": str(latest_topn) if latest_topn else None,
            "pr7_threshold_advice_latest": str(latest_advice) if latest_advice else None,
            "pr9_env_current": str(env_now_path) if env_now_path.exists() else None,
            "pr9_env_previous": str(env_prev_path) if env_prev_path.exists() else None,
        },
        "metrics": {
            "alerts_total": total,
            "alerts_sent": sent,
            "alerts_suppressed": suppressed,
            "alerts_failed": failed,
            "delivery_attempted": delivery_attempted,
            "suppression_rate_pct": round(suppression_rate, 4),
            "failure_rate_pct": round(failure_rate, 4),
            "delivery_success_rate_pct": round(delivery_success_rate, 4) if delivery_success_rate is not None else None,
            "suppression_share_pct": round(suppression_share_pct, 4),
            "delivery_summary_count": len(delivery_summaries),
            "partial_success_count": partial_success_count,
            "partial_success_rate_pct": round(partial_success_rate, 4),
            "channel_delivery_success_rate_pct": round(channel_delivery_success_rate, 4),
            "channels_ok_total": channels_ok_total,
            "channels_failed_total": channels_failed_total,
            "dead_letter_entries": dead_letters_week,
        },
        "topn": sections,
        "threshold": {
            "changed_keys": changed_keys,
            "advisor_suggestions": sug,
        },
        "week_over_week": wow,
        "degraded": {
            "missing_previous_week_baseline": not has_prev,
            "missing_topn_source": latest_topn is None,
            "missing_threshold_advice_source": latest_advice is None,
        },
    }
    history_fingerprint = payload_history_fingerprint(payload)
    payload["history_fingerprint_sha256"] = history_fingerprint

    lines: list[str] = []
    lines.append("# PR9 Weekly Alert Governance Report")
    lines.append("")
    lines.append(f"- generated_at_utc: `{now_utc}`")
    lines.append(f"- lookback_days: `{args.lookback_days}`")
    lines.append(f"- source.pr7_delivery_state: `{state_path if state_path.exists() else 'MISSING'}`")
    lines.append(f"- source.pr7_dead_letter: `{dead_letter_path if dead_letter_path.exists() else 'MISSING'}`")
    lines.append(f"- source.pr7_delivery_audit: `{audit_path if audit_path.exists() else 'MISSING'}`")
    lines.append(f"- source.pr7_topn_latest: `{latest_topn if latest_topn else 'MISSING'}`")
    lines.append(f"- source.pr7_threshold_advice_latest: `{latest_advice if latest_advice else 'MISSING'}`")
    lines.append("")

    lines.append("## 1) Alert Volume & Delivery Quality")
    lines.append(f"- alerts.total: `{total}`")
    lines.append(f"- alerts.sent: `{sent}`")
    lines.append(f"- alerts.suppressed: `{suppressed}`")
    lines.append(f"- alerts.failed: `{failed}`")
    lines.append(f"- suppression_rate: `{suppression_rate:.2f}%`")
    lines.append(f"- failure_rate: `{failure_rate:.2f}%`")
    lines.append(f"- delivery_attempted: `{delivery_attempted}`")
    lines.append(f"- delivery_success_rate: `{fmt_pct(delivery_success_rate)}`")
    lines.append(f"- delivery_summary_count: `{len(delivery_summaries)}`")
    lines.append(f"- partial_success_count: `{partial_success_count}`")
    lines.append(f"- partial_success_rate: `{partial_success_rate:.2f}%`")
    lines.append(f"- channel_delivery_success_rate: `{channel_delivery_success_rate:.2f}%`")
    lines.append(f"- channels_ok_total: `{channels_ok_total}`")
    lines.append(f"- channels_failed_total: `{channels_failed_total}`")
    lines.append(f"- suppression_share: `{suppression_share_pct:.2f}%`")
    lines.append(f"- dead_letter_entries_last_{args.lookback_days}d: `{dead_letters_week}`")
    lines.append("")

    lines.append("## 2) Week-over-Week Diff (vs last baseline)")
    if has_prev:
        lines.append(f"- baseline_json: `{prev_week_json_path}`")
        lines.append(f"- alerts.total Δ: `{fmt_delta(wow['alerts_total_delta'])}`")
        lines.append(f"- suppression_rate Δ: `{fmt_delta(float(wow['suppression_rate_pct_delta']), 'pp')}`")
        lines.append(f"- failure_rate Δ: `{fmt_delta(float(wow['failure_rate_pct_delta']), 'pp')}`")
        lines.append(
            f"- delivery_success_rate Δ: `{fmt_delta(float(wow['delivery_success_rate_pct_delta']), 'pp')}`"
            if wow["delivery_success_rate_pct_delta"] is not None
            else "- delivery_success_rate Δ: `n/a`"
        )
        lines.append(f"- suppression_share Δ: `{fmt_delta(float(wow['suppression_share_pct_delta']), 'pp')}`")
        lines.append(f"- threshold_changed_keys Δ: `{fmt_delta(int(wow['threshold_changed_keys_delta']))}`")
    else:
        lines.append("- baseline unavailable: no previous weekly JSON snapshot found (`run/pr9/history/weekly-alert-governance-*.json`).")
    lines.append("")

    lines.append(f"## 3) TopN Anomalies (latest PR7, top_n={max(1, args.top_n)})")

    def emit_top(title: str, rows: list[str]) -> None:
        lines.append(f"### {title}")
        if rows:
            for i, r in enumerate(rows[: max(1, args.top_n)], 1):
                lines.append(f"{i}. {r}")
        else:
            lines.append("- no data / section empty")
        lines.append("")

    emit_top("Unresolved Tasks", sections.get("unresolved", []))
    emit_top("Forfeit Spikes", sections.get("forfeit", []))
    emit_top("Escrow Lingering", sections.get("escrow", []))

    lines.append("## 4) TopN Changes vs Last Week")

    def emit_topn_diff(label: str, diff_obj: dict[str, Any]) -> None:
        lines.append(f"### {label}")
        if not has_prev:
            lines.append("- baseline unavailable")
            lines.append("")
            return
        entered = diff_obj.get("entered", [])
        exited = diff_obj.get("exited", [])
        rank_shift = diff_obj.get("rank_shift", [])
        if not entered and not exited and not rank_shift:
            lines.append("- no changes")
            lines.append("")
            return
        if entered:
            lines.append("- entered:")
            for x in entered:
                lines.append(f"  - {x}")
        if exited:
            lines.append("- exited:")
            for x in exited:
                lines.append(f"  - {x}")
        if rank_shift:
            lines.append("- rank_shift:")
            for x in rank_shift:
                lines.append(f"  - {x['item']}: {x['from']} -> {x['to']} (Δrank={x['delta_rank']:+d})")
        lines.append("")

    emit_topn_diff("Unresolved Tasks", wow["topn"]["unresolved"])
    emit_topn_diff("Forfeit Spikes", wow["topn"]["forfeit"])
    emit_topn_diff("Escrow Lingering", wow["topn"]["escrow"])

    lines.append("## 5) Threshold Suggestion Changes")
    if changed_keys:
        lines.append("### env diff (previous -> current)")
        for item in changed_keys:
            lines.append(f"- `{item['key']}`: `{item['old']}` -> `{item['new']}`")
    else:
        lines.append("- no env value changed vs run/pr9/alert-thresholds.previous.env")
    lines.append("")

    if has_prev:
        new_keys = wow.get("threshold_new_keys_vs_last_week", [])
        removed_keys = wow.get("threshold_removed_keys_vs_last_week", [])
        lines.append("### changed keys vs last week")
        lines.append(f"- newly_changed_keys: `{len(new_keys)}`")
        for k in new_keys:
            lines.append(f"  - {k}")
        lines.append(f"- no_longer_changed_keys: `{len(removed_keys)}`")
        for k in removed_keys:
            lines.append(f"  - {k}")
        lines.append("")

    if sug:
        lines.append("### advisor suggestions")
        for key in ["unresolved_challenges", "forfeits_daily_increase", "escrow_nonzero_hours"]:
            item = sug.get(key, {}) if isinstance(sug.get(key, {}), dict) else {}
            if not item:
                continue
            lines.append(
                f"- `{key}`: warn=`{item.get('warn', 'n/a')}` fail=`{item.get('fail', 'n/a')}` mode=`{item.get('mode', 'n/a')}` reason=`{item.get('reason', 'n/a')}`"
            )
    else:
        lines.append("- threshold-advice unavailable")
    lines.append("")

    lines.append("## 6) Nightly Integration (non-blocking)")
    lines.append("- Recommended workflow step: run this script with `continue-on-error: true` after PR7/PR6 summary steps.")
    lines.append("- Artifact paths: `run/pr9/**`, including both `.md` and `.json`.")
    lines.append("- Optional Step Summary append: embed `run/pr9/weekly-alert-governance.md` for operator visibility.")
    lines.append("")

    lines.append("## 7) Repro Commands")
    lines.append("```bash")
    lines.append("python3 scripts/v2/pr9_weekly_alert_governance.py \\")
    lines.append("  --lookback-days 7 \\")
    lines.append("  --top-n 5 \\")
    lines.append("  --out run/pr9/weekly-alert-governance.md \\")
    lines.append("  --json-out run/pr9/weekly-alert-governance.json")
    lines.append("```")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out_json.parent.mkdir(parents=True, exist_ok=True)
    rendered_json = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    out_json.write_text(rendered_json, encoding="utf-8")

    history_dir.mkdir(parents=True, exist_ok=True)
    snapshot_name = f"weekly-alert-governance-{now_dt.strftime('%Y%m%dT%H%M%SZ')}.json"
    snapshot_path = history_dir / snapshot_name
    latest_snapshot = None
    history_candidates = sorted(history_dir.glob("weekly-alert-governance-*.json"))
    if history_candidates:
        latest_snapshot = history_candidates[-1]

    wrote_snapshot = False
    if latest_snapshot is None:
        snapshot_path.write_text(rendered_json, encoding="utf-8")
        wrote_snapshot = True
    else:
        latest_payload = safe_json(latest_snapshot)
        latest_fingerprint = latest_payload.get("history_fingerprint_sha256") if isinstance(latest_payload, dict) else None
        if latest_fingerprint != history_fingerprint:
            snapshot_path.write_text(rendered_json, encoding="utf-8")
            wrote_snapshot = True

    print(f"[OK] wrote {out_md}")
    print(f"[OK] wrote {out_json}")
    if wrote_snapshot:
        print(f"[OK] wrote {snapshot_path}")
    else:
        print(f"[OK] skipped duplicate history snapshot (fingerprint={history_fingerprint})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
