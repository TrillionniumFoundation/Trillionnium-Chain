#!/usr/bin/env python3
"""PR-7 alert delivery bridge for PR-6 report output.

Minimal reliable path:
- Read PR-6 summary.txt (key=value lines)
- Trigger delivery on WARN/FAIL (configurable)
- Channel config from env (Slack webhook or Telegram bot)
- Dedup window to avoid repeated alert storms
- Supports DRY_RUN=1 without real secrets
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SEVERITY = {"PASS": 0, "WARN": 1, "FAIL": 2}


def parse_report(path: Path) -> dict[str, str]:
    kv: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("-"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def should_trigger(status: str, min_level: str) -> bool:
    return SEVERITY.get(status, -1) >= SEVERITY.get(min_level, 1)


def mk_fingerprint(report: dict[str, str]) -> str:
    key_fields = [
        report.get("alert_code", "PR6_ALERT_RULES"),
        report.get("status", "UNKNOWN"),
        report.get("rule.unresolved_challenges.status", ""),
        report.get("rule.forfeits_daily_increase.status", ""),
        report.get("rule.escrow_nonzero_hours.status", ""),
        report.get("rule.unresolved_challenges.value", ""),
        report.get("rule.forfeits_daily_increase.value", ""),
        report.get("rule.escrow_nonzero_hours.value", ""),
    ]
    digest = hashlib.sha256("|".join(key_fields).encode("utf-8")).hexdigest()
    return digest[:24]


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def in_dedup_window(state: dict, fingerprint: str, now_ts: int, dedup_seconds: int) -> bool:
    last = state.get("last_sent", {}).get(fingerprint)
    if not isinstance(last, int):
        return False
    return now_ts - last < dedup_seconds


def build_message(report: dict[str, str], report_path: Path) -> str:
    status = report.get("status", "UNKNOWN")
    code = report.get("alert_code", "PR6_ALERT_RULES")
    msg = report.get("alert_message", "")
    ts = report.get("generated_at_utc", dt.datetime.now(dt.timezone.utc).isoformat())
    unresolved = report.get("rule.unresolved_challenges.value", "?")
    forfeits = report.get("rule.forfeits_daily_increase.value", "?")
    escrow_h = report.get("rule.escrow_nonzero_hours.value", "?")
    return (
        f"[{code}][{status}] {msg}\n"
        f"- unresolved={unresolved}, forfeits_daily_increase={forfeits}, escrow_nonzero_hours={escrow_h}\n"
        f"- generated_at_utc={ts}\n"
        f"- report={report_path}"
    )


def post_json(url: str, payload: dict) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body


def send_slack(webhook: str, text: str) -> None:
    code, body = post_json(webhook, {"text": text})
    if code < 200 or code >= 300:
        raise RuntimeError(f"slack webhook failed status={code} body={body[:200]}")


def send_telegram(bot_token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    code, body = post_json(url, payload)
    if code < 200 or code >= 300:
        raise RuntimeError(f"telegram send failed status={code} body={body[:200]}")


def send_imessage(to: str, text: str) -> None:
    cmd = ["imsg", "send", "--to", to, "--service", "imessage", "--text", text]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"imessage send failed rc={proc.returncode}: {err[:300]}")


def main() -> int:
    ap = argparse.ArgumentParser(description="PR-7 alert delivery bridge")
    ap.add_argument("--report", required=True, help="PR6 summary.txt path")
    ap.add_argument("--state-file", default=os.environ.get("ALERT_NOTIFY_STATE_FILE", "run/pr7-alert-delivery/state.json"))
    ap.add_argument("--min-level", default=os.environ.get("ALERT_NOTIFY_MIN_LEVEL", "WARN"), choices=["WARN", "FAIL"])
    ap.add_argument("--dedup-seconds", type=int, default=int(os.environ.get("ALERT_NOTIFY_DEDUP_SECONDS", "1800")))
    ap.add_argument("--channel", default=os.environ.get("ALERT_NOTIFY_CHANNEL", "slack"), choices=["slack", "telegram", "imessage"])
    ap.add_argument("--dry-run", action="store_true", default=os.environ.get("DRY_RUN", "0") == "1")
    args = ap.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[PR7][FAIL] report not found: {report_path}", file=sys.stderr)
        return 2

    report = parse_report(report_path)
    status = report.get("status", "UNKNOWN")
    if status not in SEVERITY:
        print(f"[PR7][FAIL] invalid status in report: {status}", file=sys.stderr)
        return 2

    if not should_trigger(status, args.min_level):
        print(f"[PR7] skip: status={status} below min_level={args.min_level}")
        return 0

    now_ts = int(dt.datetime.now(dt.timezone.utc).timestamp())
    fingerprint = mk_fingerprint(report)
    state_path = Path(args.state_file)
    state = load_state(state_path)

    if in_dedup_window(state, fingerprint, now_ts, args.dedup_seconds):
        print(f"[PR7] dedup suppressed: fingerprint={fingerprint} window={args.dedup_seconds}s")
        return 0

    text = build_message(report, report_path)

    if args.dry_run:
        print("[PR7] DRY_RUN=1, would send alert:")
        print(text)
    else:
        try:
            if args.channel == "slack":
                webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
                if not webhook:
                    raise RuntimeError("SLACK_WEBHOOK_URL is required for channel=slack")
                send_slack(webhook, text)
            elif args.channel == "telegram":
                token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
                chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
                if not token or not chat_id:
                    raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required for channel=telegram")
                send_telegram(token, chat_id, text)
            else:
                to = os.environ.get("IMESSAGE_TO", "").strip()
                if not to:
                    raise RuntimeError("IMESSAGE_TO is required for channel=imessage")
                send_imessage(to, text)
        except (RuntimeError, urllib.error.URLError) as e:
            print(f"[PR7][FAIL] notify delivery failed: {e}", file=sys.stderr)
            return 3

    state.setdefault("last_sent", {})[fingerprint] = now_ts
    save_state(state_path, state)
    print(f"[PR7] sent status={status} channel={args.channel} fingerprint={fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
