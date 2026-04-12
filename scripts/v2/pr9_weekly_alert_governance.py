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
import shlex
from pathlib import Path


ENV_RE = re.compile(r"^([A-Z0-9_]+)=(.*)$")
ENV_KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def safe_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}



def parse_env_line(raw: str) -> tuple[str, str] | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    try:
        tokens = shlex.split(line, comments=True, posix=True)
    except ValueError:
        tokens = []

    if tokens:
        if tokens[0] == "export":
            tokens = tokens[1:]
        if len(tokens) == 1 and "=" in tokens[0]:
            key, value = tokens[0].split("=", 1)
            if ENV_KEY_RE.fullmatch(key):
                return key, value
            return None

    normalized = line
    if normalized.startswith("export "):
        normalized = normalized[len("export ") :].lstrip()
    m = ENV_RE.match(normalized)
    if not m:
        return None
    key, value = m.group(1), m.group(2)
    if not ENV_KEY_RE.fullmatch(key):
        return None
    return key, value



def parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_env_line(raw)
        if parsed is None:
            continue
        key, value = parsed
        out[key] = value
    return out



def latest_file(pattern: str) -> Path | None:
    matches = sorted(Path.cwd().glob(pattern))
    return matches[-1] if matches else None



def latest_history_snapshot(root: Path) -> tuple[Path | None, dict]:
    matches = sorted((root / "run" / "pr9" / "history").glob("weekly-alert-governance-*.json"))
    if not matches:
        return None, {}
    latest = matches[-1]
    return latest, safe_json(latest)



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



def cleaned_top_rows(rows: list[str], top_n: int) -> list[str]:
    cleaned_rows: list[str] = []
    for row in rows[: max(1, top_n)]:
        cleaned = re.sub(r"^\d+\.\s*", "", row)
        cleaned = re.sub(r"^-\s*", "", cleaned)
        cleaned_rows.append(cleaned)
    return cleaned_rows



def extract_previous_changed_keys(snapshot: dict) -> list[str]:
    threshold = snapshot.get("threshold", {}) if isinstance(snapshot.get("threshold", {}), dict) else {}
    changed = threshold.get("changed_keys", [])
    if not isinstance(changed, list):
        return []

    keys: list[str] = []
    for item in changed:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if isinstance(key, str):
            keys.append(key)
    return sorted(set(keys))



def build_week_over_week(current_changed_keys: list[dict[str, str]], baseline_path: Path | None, baseline: dict) -> dict:
    current_keys = sorted({item["key"] for item in current_changed_keys})
    if baseline_path is None:
        return {
            "available": False,
            "baseline_json": None,
            "threshold_changed_keys_delta": len(current_keys),
            "threshold_new_keys_vs_last_week": current_keys,
            "threshold_removed_keys_vs_last_week": [],
        }

    previous_keys = extract_previous_changed_keys(baseline)
    previous_key_set = set(previous_keys)
    current_key_set = set(current_keys)
    return {
        "available": True,
        "baseline_json": str(baseline_path),
        "threshold_changed_keys_delta": len(current_keys) - len(previous_keys),
        "threshold_new_keys_vs_last_week": [key for key in current_keys if key not in previous_key_set],
        "threshold_removed_keys_vs_last_week": [key for key in previous_keys if key not in current_key_set],
    }



def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PR9 weekly alert governance markdown")
    ap.add_argument("--lookback-days", type=int, default=7)
    ap.add_argument("--top-n", type=int, default=5)
    ap.add_argument("--out", default="run/pr9/weekly-alert-governance.md")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()

    if args.lookback_days < 1:
        ap.error("--lookback-days must be >= 1")
    if args.top_n < 1:
        ap.error("--top-n must be >= 1")

    root = Path.cwd()
    out_path = root / args.out
    json_out_path = (root / args.json_out) if args.json_out else None

    state_path = root / "run/pr7-alert-delivery/state.json"
    dead_letter_path = root / "run/pr7-alert-delivery/dead-letter.jsonl"
    latest_topn = latest_file("run/pr7-topn/*/topn-anomaly-summary.md")
    latest_advice = latest_file("run/pr7-threshold-advisor/*/threshold-advice.json")
    env_now_path = root / "run/pr9/alert-thresholds.env"
    env_prev_path = root / "run/pr9/alert-thresholds.previous.env"
    baseline_path, baseline = latest_history_snapshot(root)

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
    changed_keys: list[dict[str, str]] = []
    for key in sorted(set(env_now.keys()) | set(env_prev.keys())):
        if env_now.get(key) != env_prev.get(key):
            changed_keys.append(
                {
                    "key": key,
                    "old": env_prev.get(key, "(missing)"),
                    "new": env_now.get(key, "(missing)"),
                }
            )

    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    week_over_week = build_week_over_week(changed_keys, baseline_path, baseline)
    topn_payload = {
        "unresolved": cleaned_top_rows(sections.get("unresolved", []), args.top_n),
        "forfeit": cleaned_top_rows(sections.get("forfeit", []), args.top_n),
        "escrow": cleaned_top_rows(sections.get("escrow", []), args.top_n),
    }

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
            for i, cleaned in enumerate(cleaned_top_rows(rows, args.top_n), 1):
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
        for item in changed_keys:
            lines.append(f"- `{item['key']}`: `{item['old']}` -> `{item['new']}`")
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
    if args.json_out:
        lines.append(f"  --json-out {args.json_out} \\")
    lines.append(f"  --out {args.out}")
    lines.append("```")

    payload = {
        "generated_at_utc": now_utc,
        "lookback_days": args.lookback_days,
        "sources": {
            "pr7_delivery_state": str(state_path) if state_path.exists() else "MISSING",
            "pr7_dead_letter": str(dead_letter_path) if dead_letter_path.exists() else "MISSING",
            "pr7_topn_latest": str(latest_topn) if latest_topn else "MISSING",
            "pr7_threshold_advice_latest": str(latest_advice) if latest_advice else "MISSING",
        },
        "metrics": {
            "alerts_total": total,
            "alerts_sent": sent,
            "alerts_suppressed": suppressed,
            "alerts_failed": failed,
            "suppression_rate_pct": suppression_rate,
            "failure_rate_pct": failure_rate,
            "dead_letter_entries_last_nd": dead_letters_week,
        },
        "topn": topn_payload,
        "threshold": {
            "changed_keys": changed_keys,
        },
        "week_over_week": week_over_week,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if json_out_path is not None:
        json_out_path.parent.mkdir(parents=True, exist_ok=True)
        json_out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"[OK] wrote {out_path}")
    if json_out_path is not None:
        print(f"[OK] wrote {json_out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
