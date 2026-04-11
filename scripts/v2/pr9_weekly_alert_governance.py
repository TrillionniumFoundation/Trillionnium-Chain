#!/usr/bin/env python3
"""PR9: generate weekly alert governance report (markdown).

Data sources (best effort):
- run/pr7-alert-delivery/state.json / dead-letter.jsonl
- run/pr7-topn/*/topn-anomaly-summary.md
- run/pr7-threshold-advisor/*/threshold-advice.json
- run/pr9/alert-thresholds.env and run/pr9/alert-thresholds.previous.env

Output:
- run/pr9/weekly-alert-governance.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path


ENV_RE = re.compile(r"^([A-Z0-9_]+)=(.*)$")


def safe_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


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


def read_dead_letters(path: Path, lookback_days: int) -> list[dict]:
    if not path.exists():
        return []
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max(1, lookback_days))
    rows: list[dict] = []
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
        ts = obj.get("created_at_utc", "")
        in_window = True
        if isinstance(ts, str) and ts:
            try:
                t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                in_window = t >= cutoff
            except Exception:
                in_window = True
        if in_window:
            rows.append(obj)
    return rows


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
            sections[mode].append(line.strip())
    return sections


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PR9 weekly alert governance markdown")
    ap.add_argument("--lookback-days", type=int, default=7)
    ap.add_argument("--top-n", type=int, default=5)
    ap.add_argument("--out", default="run/pr9/weekly-alert-governance.md")
    args = ap.parse_args()

    if args.lookback_days < 1:
        ap.error("--lookback-days must be >= 1")
    if args.top_n < 1:
        ap.error("--top-n must be >= 1")

    root = Path.cwd()
    out_path = root / args.out

    state_path = root / "run/pr7-alert-delivery/state.json"
    dead_letter_path = root / "run/pr7-alert-delivery/dead-letter.jsonl"
    latest_topn = latest_file("run/pr7-topn/*/topn-anomaly-summary.md")
    latest_advice = latest_file("run/pr7-threshold-advisor/*/threshold-advice.json")
    env_now_path = root / "run/pr9/alert-thresholds.env"
    env_prev_path = root / "run/pr9/alert-thresholds.previous.env"

    state = safe_json(state_path)
    stats = state.get("stats", {}) if isinstance(state.get("stats", {}), dict) else {}
    sent = int(stats.get("alerts_sent", 0) or 0)
    suppressed = int(stats.get("alerts_suppressed", 0) or 0)
    failed = int(stats.get("alerts_failed", 0) or 0)
    total = max(0, sent + suppressed + failed)

    suppression_rate = (suppressed / total * 100.0) if total > 0 else 0.0
    failure_rate = (failed / total * 100.0) if total > 0 else 0.0

    dead_letters = read_dead_letters(dead_letter_path, lookback_days=args.lookback_days)
    dead_letters_week = len(dead_letters)

    sections = extract_topn_sections(latest_topn) if latest_topn else {"unresolved": [], "forfeit": [], "escrow": []}

    advice = safe_json(latest_advice) if latest_advice else {}
    sug = advice.get("suggestions", {}) if isinstance(advice.get("suggestions", {}), dict) else {}

    env_now = parse_env(env_now_path)
    env_prev = parse_env(env_prev_path)
    changed_keys = []
    for k in sorted(set(env_now.keys()) | set(env_prev.keys())):
        if env_now.get(k) != env_prev.get(k):
            changed_keys.append((k, env_prev.get(k, "(missing)"), env_now.get(k, "(missing)")))

    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines: list[str] = []
    lines.append("# PR9 Weekly Alert Governance Report")
    lines.append("")
    lines.append(f"- generated_at_utc: `{now_utc}`")
    lines.append(f"- lookback_days: `{args.lookback_days}`")
    lines.append(f"- source.pr7_delivery_state: `{state_path if state_path.exists() else 'MISSING'}`")
    lines.append(f"- source.pr7_dead_letter: `{dead_letter_path if dead_letter_path.exists() else 'MISSING'}`")
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
    lines.append(f"- dead_letter_entries_last_{args.lookback_days}d: `{dead_letters_week}`")
    lines.append("")

    lines.append(f"## 2) TopN Anomalies (latest PR7, top_n={max(1, args.top_n)})")

    def emit_top(title: str, rows: list[str]) -> None:
        lines.append(f"### {title}")
        if rows:
            for i, r in enumerate(rows[: max(1, args.top_n)], 1):
                cleaned = re.sub(r"^\d+\.\s*", "", r)
                cleaned = re.sub(r"^-\s*", "", cleaned)
                lines.append(f"{i}. {cleaned}")
        else:
            lines.append("- no data / section empty")
        lines.append("")

    emit_top("Unresolved Tasks", sections.get("unresolved", []))
    emit_top("Forfeit Spikes", sections.get("forfeit", []))
    emit_top("Escrow Lingering", sections.get("escrow", []))

    lines.append("## 3) Threshold Suggestion Changes")
    if changed_keys:
        lines.append("### env diff (previous -> current)")
        for k, old, new in changed_keys:
            lines.append(f"- `{k}`: `{old}` -> `{new}`")
    else:
        lines.append("- no env value changed vs run/pr9/alert-thresholds.previous.env")
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

    lines.append("## 4) Nightly Integration (non-blocking)")
    lines.append("- Recommended workflow step: run this script with `continue-on-error: true` after PR7/PR6 summary steps.")
    lines.append("- Artifact path: `run/pr9/**` (upload with nightly artifacts).")
    lines.append("- Optional Step Summary append: embed `run/pr9/weekly-alert-governance.md` for operator visibility.")
    lines.append("")

    lines.append("## 5) Repro Commands")
    lines.append("```bash")
    lines.append("python3 scripts/v2/pr9_weekly_alert_governance.py \\")
    lines.append("  --lookback-days 7 \\")
    lines.append("  --top-n 5 \\")
    lines.append("  --out run/pr9/weekly-alert-governance.md")
    lines.append("```")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[OK] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
