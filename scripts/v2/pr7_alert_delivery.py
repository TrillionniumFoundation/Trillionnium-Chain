#!/usr/bin/env python3
"""PR-7 alert delivery bridge for PR-6 report output.

Reliable path:
- Read PR-6 summary.txt (key=value lines)
- Trigger delivery on severity thresholds
- Channel config from env (Slack webhook / Telegram bot / iMessage)
- Alert-noise controls: level mapping, same-class aggregation, per-level cooldown
- Exponential backoff retry on delivery failures
- Dead-letter on retry exhaustion
- Supports DRY_RUN=1 and failure simulation for tests
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

SEVERITY = {"INFO": 0, "WARN": 1, "CRITICAL": 2}
STATUS_TO_LEVEL = {"PASS": "INFO", "WARN": "WARN", "FAIL": "CRITICAL"}


def level_from_status(report: dict[str, str]) -> str | None:
    status = report.get("status", "").strip().upper()
    return STATUS_TO_LEVEL.get(status)


def validate_status_alert_level_consistency(report: dict[str, str]) -> tuple[bool, str]:
    """Return (ok, reason). Reject contradictory status/alert_level pairs."""
    mapped = level_from_status(report)
    alert_level = report.get("alert_level", "").strip().upper()

    # If either side is missing/unknown, keep backward-compatible behavior and let normalize_level decide.
    if not mapped or not alert_level or alert_level not in SEVERITY:
        return True, ""

    if mapped != alert_level:
        status = report.get("status", "").strip().upper()
        return False, f"inconsistent_status_alert_level: status={status}=>{mapped}, alert_level={alert_level}"

    return True, ""


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


def normalize_level(report: dict[str, str]) -> str:
    alert_level = report.get("alert_level", "").strip().upper()
    if alert_level in SEVERITY:
        return alert_level

    level = level_from_status(report)
    if level:
        return level

    status = report.get("status", "").strip().upper()
    raise ValueError(f"invalid status/alert_level in report: status={status!r} alert_level={alert_level!r}")


def normalize_min_level(raw: str) -> str:
    v = raw.strip().upper()
    if v == "FAIL":
        return "CRITICAL"
    if v == "PASS":
        return "INFO"
    if v in SEVERITY:
        return v
    raise ValueError(f"invalid min level: {raw}")


def should_trigger(level: str, min_level: str) -> bool:
    return SEVERITY[level] >= SEVERITY[min_level]


def mk_exact_fingerprint(report: dict[str, str], level: str) -> str:
    key_fields = [
        report.get("alert_code", "PR6_ALERT_RULES"),
        level,
        report.get("rule.unresolved_challenges.status", ""),
        report.get("rule.forfeits_daily_increase.status", ""),
        report.get("rule.escrow_nonzero_hours.status", ""),
        report.get("rule.unresolved_challenges.value", ""),
        report.get("rule.forfeits_daily_increase.value", ""),
        report.get("rule.escrow_nonzero_hours.value", ""),
    ]
    digest = hashlib.sha256("|".join(key_fields).encode("utf-8")).hexdigest()
    return digest[:24]


def mk_class_fingerprint(report: dict[str, str], level: str) -> str:
    key_fields = [
        report.get("alert_code", "PR6_ALERT_RULES"),
        level,
        report.get("rule.unresolved_challenges.status", ""),
        report.get("rule.forfeits_daily_increase.status", ""),
        report.get("rule.escrow_nonzero_hours.status", ""),
    ]
    digest = hashlib.sha256("|".join(key_fields).encode("utf-8")).hexdigest()
    return digest[:24]


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def ensure_stats(state: dict) -> dict:
    stats = state.setdefault("stats", {})
    stats.setdefault("alerts_sent", 0)
    stats.setdefault("alerts_suppressed", 0)
    stats.setdefault("alerts_failed", 0)
    return stats


def record_delivery(state: dict, *, event: str, reason: str, channel: str, report_status: str, fingerprint: str, report_path: Path) -> None:
    state["last_delivery"] = {
        "event": event,
        "reason": reason,
        "channel": channel,
        "report_status": report_status,
        "fingerprint": fingerprint,
        "report": str(report_path),
        "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def in_window(last_ts: int | None, now_ts: int, window_seconds: int) -> bool:
    if not isinstance(last_ts, int):
        return False
    return now_ts - last_ts < max(0, window_seconds)


def level_cooldowns_from_args(args: argparse.Namespace) -> dict[str, int]:
    # Backward compatibility: if per-level cooldown not provided, fallback to ALERT_NOTIFY_DEDUP_SECONDS.
    base = max(0, args.dedup_seconds)
    return {
        "INFO": max(0, args.cooldown_info if args.cooldown_info is not None else base),
        "WARN": max(0, args.cooldown_warn if args.cooldown_warn is not None else base),
        "CRITICAL": max(0, args.cooldown_critical if args.cooldown_critical is not None else min(300, base)),
    }


def parse_hhmm(raw: str) -> tuple[int, int]:
    s = raw.strip()
    hh, mm = s.split(":", 1)
    h = int(hh)
    m = int(mm)
    if h < 0 or h > 23 or m < 0 or m > 59:
        raise ValueError(f"invalid HH:MM value: {raw}")
    return h, m


def is_in_quiet_hours(*, now_utc: dt.datetime, tz_name: str, start_hhmm: str, end_hhmm: str) -> bool:
    local_now = now_utc.astimezone(ZoneInfo(tz_name))
    sh, sm = parse_hhmm(start_hhmm)
    eh, em = parse_hhmm(end_hhmm)
    now_m = local_now.hour * 60 + local_now.minute
    start_m = sh * 60 + sm
    end_m = eh * 60 + em
    if start_m == end_m:
        return False
    if start_m < end_m:
        return start_m <= now_m < end_m
    # cross-midnight (e.g. 23:00-08:00)
    return now_m >= start_m or now_m < end_m


def update_warn_streaks(streaks: dict, class_fp: str, now_ts: int, window_seconds: int) -> int:
    streak = streaks.get(class_fp)
    if not isinstance(streak, dict):
        streak = {"count": 0, "first_ts": now_ts, "last_ts": now_ts}

    if not isinstance(streak.get("last_ts"), int) or now_ts - int(streak["last_ts"]) >= max(0, window_seconds):
        streak = {"count": 0, "first_ts": now_ts, "last_ts": now_ts}

    streak["count"] = int(streak.get("count", 0)) + 1
    streak["last_ts"] = now_ts
    streaks[class_fp] = streak
    return int(streak["count"])


def clear_warn_streaks(streaks: dict, class_fp: str, now_ts: int) -> None:
    streaks[class_fp] = {"count": 0, "first_ts": now_ts, "last_ts": now_ts}


def update_group(groups: dict, class_fp: str, now_ts: int, aggregate_seconds: int) -> int:
    group = groups.get(class_fp)
    if not isinstance(group, dict):
        group = {"count": 0, "first_ts": now_ts, "last_ts": now_ts}

    if not isinstance(group.get("last_ts"), int) or now_ts - int(group["last_ts"]) >= max(0, aggregate_seconds):
        group = {"count": 0, "first_ts": now_ts, "last_ts": now_ts}

    group["count"] = int(group.get("count", 0)) + 1
    group["last_ts"] = now_ts
    groups[class_fp] = group
    return int(group["count"])


def clear_group(groups: dict, class_fp: str, now_ts: int) -> None:
    groups[class_fp] = {"count": 0, "first_ts": now_ts, "last_ts": now_ts}


def build_message(
    report: dict[str, str],
    report_path: Path,
    level: str,
    aggregate_count: int,
    aggregate_seconds: int,
    *,
    escalated_from_warn: bool = False,
    warn_streak_count: int = 0,
    warn_escalate_count: int = 0,
) -> str:
    status = report.get("status", "UNKNOWN")
    code = report.get("alert_code", "PR6_ALERT_RULES")
    msg = report.get("alert_message", "")
    ts = report.get("generated_at_utc", dt.datetime.now(dt.timezone.utc).isoformat())
    unresolved = report.get("rule.unresolved_challenges.value", "?")
    forfeits = report.get("rule.forfeits_daily_increase.value", "?")
    escrow_h = report.get("rule.escrow_nonzero_hours.value", "?")

    agg_line = ""
    if aggregate_count > 1:
        agg_line = f"\n- aggregated={aggregate_count} similar alerts within {aggregate_seconds}s"

    escalate_line = ""
    if escalated_from_warn:
        escalate_line = (
            "\n"
            f"- escalated_from=WARN (streak={warn_streak_count}, threshold={warn_escalate_count})"
        )

    return (
        f"[{code}][{level}] {msg}\n"
        f"- source_status={status}, unresolved={unresolved}, forfeits_daily_increase={forfeits}, escrow_nonzero_hours={escrow_h}\n"
        f"- generated_at_utc={ts}{agg_line}{escalate_line}\n"
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


def deliver_once(channel: str, text: str) -> None:
    if channel == "slack":
        webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        if not webhook:
            raise RuntimeError("SLACK_WEBHOOK_URL is required for channel=slack")
        send_slack(webhook, text)
    elif channel == "telegram":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat_id:
            raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required for channel=telegram")
        send_telegram(token, chat_id, text)
    elif channel == "imessage":
        to = os.environ.get("IMESSAGE_TO", "").strip()
        if not to:
            raise RuntimeError("IMESSAGE_TO is required for channel=imessage")
        send_imessage(to, text)
    else:
        raise RuntimeError(f"unsupported channel: {channel}")


def consume_global_retry_budget(state_file: Path, window_seconds: int, budget: int) -> bool:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    now_ts = int(time.time())
    window_seconds = max(1, int(window_seconds))

    with state_file.open("a+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.seek(0)
        raw = f.read().strip()
        try:
            state = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            state = {}

        start = int(state.get("window_start_ts", now_ts))
        used = int(state.get("retries_used", 0))
        if now_ts - start >= window_seconds:
            start = now_ts
            used = 0

        if used >= max(0, int(budget)):
            return False

        used += 1
        state = {
            "window_start_ts": start,
            "retries_used": used,
            "window_seconds": window_seconds,
            "budget": int(budget),
            "updated_at_ts": now_ts,
        }
        f.seek(0)
        f.truncate()
        f.write(json.dumps(state, ensure_ascii=False))
        f.flush()
        os.fsync(f.fileno())
        return True


def send_with_retry(
    *,
    channel: str,
    text: str,
    dry_run: bool,
    max_retries: int,
    base_backoff_ms: int,
    max_backoff_ms: int,
    dry_run_simulate_failures: int = 0,
    global_retry_budget: int = 0,
    global_retry_window_seconds: int = 300,
    global_retry_budget_state_file: str = "run/pr7-alert-delivery/retry-budget-state.json",
    retry_jitter_seed: int | None = None,
) -> tuple[bool, int, str]:
    rng = random.Random(retry_jitter_seed) if retry_jitter_seed is not None else random
    attempt = 0
    while True:
        attempt += 1
        try:
            if dry_run and attempt <= dry_run_simulate_failures:
                raise RuntimeError(f"dry-run injected failure at attempt={attempt}")
            if not dry_run:
                deliver_once(channel, text)
            return True, attempt, ""
        except (RuntimeError, urllib.error.URLError) as e:
            if attempt > max_retries:
                return False, attempt, str(e)

            if global_retry_budget > 0:
                ok_budget = consume_global_retry_budget(
                    Path(global_retry_budget_state_file),
                    global_retry_window_seconds,
                    global_retry_budget,
                )
                if not ok_budget:
                    return False, attempt, (
                        f"global retry budget exhausted: budget={global_retry_budget} "
                        f"window_seconds={global_retry_window_seconds}"
                    )

            backoff_ms = min(max_backoff_ms, base_backoff_ms * (2 ** (attempt - 1)))
            jitter_ms = rng.randint(0, max(1, backoff_ms // 10))
            sleep_ms = backoff_ms + jitter_ms
            print(
                f"[PR7][RETRY] channel={channel} attempt={attempt}/{max_retries + 1} "
                f"backoff_ms={sleep_ms} err={e}",
                file=sys.stderr,
            )
            time.sleep(sleep_ms / 1000.0)


def append_dead_letter(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def append_audit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def parse_channels_csv(raw: str) -> set[str]:
    out: set[str] = set()
    for x in raw.split(","):
        c = x.strip().lower()
        if c:
            out.add(c)
    return out


def route_targets(level: str, primary: str, backup: str | None) -> list[str]:
    targets = [primary]
    if level == "CRITICAL" and backup and backup != primary:
        targets.append(backup)
    return targets


DELIVERY_CHANNELS = {"slack", "telegram", "imessage"}
LEVEL_ROUTE_ENV = {
    "INFO": "ALERT_NOTIFY_CHANNEL_INFO",
    "WARN": "ALERT_NOTIFY_CHANNEL_WARN",
    "CRITICAL": "ALERT_NOTIFY_CHANNEL_CRITICAL",
}


def resolve_primary_channel(args: argparse.Namespace, level: str) -> str:
    """Resolve the primary route for an already-normalized effective level.

    Direct CLI use keeps the historical --primary-channel/--channel behavior.
    The PR7 gate opts into level routing only when the operator supplied neither
    ALERT_NOTIFY_PRIMARY_CHANNEL nor legacy ALERT_NOTIFY_CHANNEL. This lets a
    WARN promoted to CRITICAL select the critical route after escalation while
    preserving both explicit override contracts.
    """

    fallback = (args.primary_channel or args.channel).strip().lower()
    route_by_level = os.environ.get("PR7_ROUTE_BY_EFFECTIVE_LEVEL", "0") == "1"
    if route_by_level:
        route_env = LEVEL_ROUTE_ENV.get(level)
        candidate = (os.environ.get(route_env, "") if route_env else "").strip().lower()
        channel = candidate or fallback
    else:
        channel = fallback

    if channel not in DELIVERY_CHANNELS:
        raise ValueError(f"invalid delivery channel for effective level={level}: {channel!r}")
    return channel


def main() -> int:
    ap = argparse.ArgumentParser(description="PR-7 alert delivery bridge")
    ap.add_argument("--report", required=True, help="PR6 summary.txt path")
    ap.add_argument("--state-file", default=os.environ.get("ALERT_NOTIFY_STATE_FILE", "run/pr7-alert-delivery/state.json"))
    ap.add_argument("--dead-letter-file", default=os.environ.get("ALERT_NOTIFY_DEAD_LETTER_FILE", "run/pr7-alert-delivery/dead-letter.jsonl"))
    ap.add_argument("--min-level", default=os.environ.get("ALERT_NOTIFY_MIN_LEVEL", "WARN"))
    ap.add_argument("--dedup-seconds", type=int, default=int(os.environ.get("ALERT_NOTIFY_DEDUP_SECONDS", "1800")))
    ap.add_argument(
        "--aggregate-seconds",
        type=int,
        default=int(os.environ.get("ALERT_NOTIFY_AGGREGATE_SECONDS", os.environ.get("ALERT_NOTIFY_DEDUP_SECONDS", "1800"))),
    )
    ap.add_argument("--cooldown-info", type=int, default=(int(os.environ["ALERT_NOTIFY_COOLDOWN_INFO"]) if "ALERT_NOTIFY_COOLDOWN_INFO" in os.environ else None))
    ap.add_argument("--cooldown-warn", type=int, default=(int(os.environ["ALERT_NOTIFY_COOLDOWN_WARN"]) if "ALERT_NOTIFY_COOLDOWN_WARN" in os.environ else None))
    ap.add_argument(
        "--cooldown-critical",
        type=int,
        default=(int(os.environ["ALERT_NOTIFY_COOLDOWN_CRITICAL"]) if "ALERT_NOTIFY_COOLDOWN_CRITICAL" in os.environ else None),
    )
    ap.add_argument("--channel", default=os.environ.get("ALERT_NOTIFY_CHANNEL", "slack"), choices=["slack", "telegram", "imessage"])
    ap.add_argument("--primary-channel", choices=["slack", "telegram", "imessage"], default=os.environ.get("ALERT_NOTIFY_PRIMARY_CHANNEL", ""))
    ap.add_argument("--backup-channel", choices=["slack", "telegram", "imessage"], default=os.environ.get("ALERT_NOTIFY_BACKUP_CHANNEL", ""))
    ap.add_argument("--audit-file", default=os.environ.get("ALERT_NOTIFY_AUDIT_FILE", "run/pr7-alert-delivery/audit.jsonl"))
    ap.add_argument("--max-retries", type=int, default=int(os.environ.get("ALERT_NOTIFY_MAX_RETRIES", "3")))
    ap.add_argument("--base-backoff-ms", type=int, default=int(os.environ.get("ALERT_NOTIFY_BASE_BACKOFF_MS", "500")))
    ap.add_argument("--max-backoff-ms", type=int, default=int(os.environ.get("ALERT_NOTIFY_MAX_BACKOFF_MS", "8000")))
    ap.add_argument("--global-retry-budget", type=int, default=int(os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_BUDGET", "0")))
    ap.add_argument("--global-retry-window-seconds", type=int, default=int(os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_WINDOW_SECONDS", "300")))
    ap.add_argument("--global-retry-budget-state-file", default=os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_BUDGET_STATE_FILE", "run/pr7-alert-delivery/retry-budget-state.json"))
    ap.add_argument(
        "--retry-jitter-seed",
        type=int,
        default=(int(os.environ["ALERT_NOTIFY_RETRY_JITTER_SEED"]) if "ALERT_NOTIFY_RETRY_JITTER_SEED" in os.environ else None),
        help="optional deterministic seed for retry jitter (useful for CI replay/regression reproducibility)",
    )
    ap.add_argument("--quiet-hours-enabled", action="store_true", default=os.environ.get("ALERT_NOTIFY_QUIET_HOURS_ENABLED", "0") == "1")
    ap.add_argument("--quiet-hours-start", default=os.environ.get("ALERT_NOTIFY_QUIET_HOURS_START", "23:00"))
    ap.add_argument("--quiet-hours-end", default=os.environ.get("ALERT_NOTIFY_QUIET_HOURS_END", "08:00"))
    ap.add_argument("--quiet-hours-tz", default=os.environ.get("ALERT_NOTIFY_QUIET_HOURS_TZ", "Asia/Shanghai"))
    ap.add_argument("--warn-escalate-count", type=int, default=int(os.environ.get("ALERT_NOTIFY_WARN_ESCALATE_COUNT", "0")))
    ap.add_argument("--warn-escalate-window-seconds", type=int, default=int(os.environ.get("ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS", "3600")))
    ap.add_argument("--dry-run", action="store_true", default=os.environ.get("DRY_RUN", "0") == "1")
    ap.add_argument(
        "--dry-run-simulate-failures",
        type=int,
        default=int(os.environ.get("ALERT_NOTIFY_DRY_RUN_SIMULATE_FAILURES", "0")),
        help="only in dry-run mode: inject N failures before success",
    )
    ap.add_argument(
        "--dry-run-fail-channels",
        default=os.environ.get("ALERT_NOTIFY_DRY_RUN_FAIL_CHANNELS", ""),
        help="comma-separated channels to force fail in dry-run, e.g. 'imessage,slack'",
    )
    args = ap.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[PR7][FAIL] report not found: {report_path}", file=sys.stderr)
        return 2

    report = parse_report(report_path)
    now_utc = dt.datetime.now(dt.timezone.utc)
    now_ts = int(now_utc.timestamp())
    now_iso = now_utc.isoformat()

    try:
        original_level = normalize_level(report)
        level = original_level
        min_level = normalize_min_level(args.min_level)
    except ValueError as e:
        print(f"[PR7][FAIL] {e}", file=sys.stderr)
        return 2

    consistency_ok, consistency_reason = validate_status_alert_level_consistency(report)

    try:
        primary_channel = resolve_primary_channel(args, original_level)
    except ValueError as e:
        print(f"[PR7][FAIL] {e}", file=sys.stderr)
        return 2
    backup_channel = (args.backup_channel or "").strip().lower() or None
    dry_run_fail_channels = parse_channels_csv(args.dry_run_fail_channels)

    state_path = Path(args.state_file)
    state = load_state(state_path)
    state.setdefault("last_sent", {})  # backward compatible exact dedup store
    state.setdefault("last_sent_exact", {})
    state.setdefault("last_sent_class", {})
    state.setdefault("groups", {})
    state.setdefault("warn_streaks", {})
    stats = ensure_stats(state)

    if not consistency_ok:
        stats["alerts_suppressed"] += 1
        mismatch_fp = mk_class_fingerprint(report, level)
        record_delivery(
            state,
            event="suppressed",
            reason=consistency_reason,
            channel=primary_channel,
            report_status=report.get("status", "UNKNOWN"),
            fingerprint=mismatch_fp,
            report_path=report_path,
        )
        append_audit(
            Path(args.audit_file),
            {
                "at_utc": now_iso,
                "fingerprint": mismatch_fp,
                "class_fingerprint": mismatch_fp,
                "level": level,
                "report_path": str(report_path),
                "channel": primary_channel,
                "reason": consistency_reason,
                "ok": False,
                "attempts": 0,
                "error": consistency_reason,
                "dry_run": args.dry_run,
                "rejected": True,
            },
        )
        save_state(state_path, state)
        print(f"[PR7] suppressed(consistency): {consistency_reason}")
        return 0

    if args.quiet_hours_enabled and original_level != "CRITICAL":
        try:
            in_quiet = is_in_quiet_hours(
                now_utc=now_utc,
                tz_name=args.quiet_hours_tz,
                start_hhmm=args.quiet_hours_start,
                end_hhmm=args.quiet_hours_end,
            )
        except Exception as e:
            print(f"[PR7][FAIL] invalid quiet-hours config: {e}", file=sys.stderr)
            return 2
        if in_quiet:
            stats["alerts_suppressed"] += 1
            qh_fp = mk_class_fingerprint(report, original_level)
            record_delivery(
                state,
                event="suppressed",
                reason=(
                    f"quiet_hours_{args.quiet_hours_start}-{args.quiet_hours_end}@{args.quiet_hours_tz}"
                ),
                channel=primary_channel,
                report_status=report.get("status", "UNKNOWN"),
                fingerprint=qh_fp,
                report_path=report_path,
            )
            save_state(state_path, state)
            print(
                f"[PR7] suppressed(quiet-hours): level={original_level} window={args.quiet_hours_start}-{args.quiet_hours_end} tz={args.quiet_hours_tz}"
            )
            return 0

    escalated_from_warn = False
    warn_streak_count = 0
    warn_escalate_count = max(0, args.warn_escalate_count)
    if level == "WARN" and warn_escalate_count > 0:
        warn_class_fp = mk_class_fingerprint(report, "WARN")
        warn_streak_count = update_warn_streaks(
            state["warn_streaks"], warn_class_fp, now_ts, max(0, args.warn_escalate_window_seconds)
        )
        if warn_streak_count >= warn_escalate_count:
            level = "CRITICAL"
            escalated_from_warn = True

    try:
        primary_channel = resolve_primary_channel(args, level)
    except ValueError as e:
        print(f"[PR7][FAIL] {e}", file=sys.stderr)
        return 2

    if not should_trigger(level, min_level):
        skip_reason = f"level={level} below min_level={min_level}"
        skip_fp = mk_class_fingerprint(report, level)
        record_delivery(
            state,
            event="skipped_min_level",
            reason=skip_reason,
            channel=primary_channel,
            report_status=report.get("status", "UNKNOWN"),
            fingerprint=skip_fp,
            report_path=report_path,
        )
        append_audit(
            Path(args.audit_file),
            {
                "at_utc": now_iso,
                "record_type": "delivery_summary",
                "fingerprint": skip_fp,
                "class_fingerprint": skip_fp,
                "level": level,
                "report_path": str(report_path),
                "channels_total": 0,
                "channels_ok": 0,
                "channels_failed": 0,
                "attempts": 0,
                "dry_run": args.dry_run,
                "event": "skipped_min_level",
                "ok": True,
                "reason": skip_reason,
                "primary_channel": primary_channel,
            },
        )
        print(f"[PR7] skip: {skip_reason}")
        save_state(state_path, state)
        return 0

    exact_fp = mk_exact_fingerprint(report, level)
    class_fp = mk_class_fingerprint(report, level)

    cooldowns = level_cooldowns_from_args(args)
    cooldown = cooldowns[level]

    # backward compatibility: old last_sent also works as exact dedup source
    last_exact_ts = state["last_sent_exact"].get(exact_fp)
    if not isinstance(last_exact_ts, int):
        last_exact_ts = state["last_sent"].get(exact_fp)

    # strict dedup for identical event
    if in_window(last_exact_ts, now_ts, cooldown):
        count = update_group(state["groups"], class_fp, now_ts, args.aggregate_seconds)
        stats["alerts_suppressed"] += 1
        record_delivery(
            state,
            event="suppressed",
            reason=f"exact_dedup_{cooldown}s",
            channel=primary_channel,
            report_status=report.get("status", "UNKNOWN"),
            fingerprint=exact_fp,
            report_path=report_path,
        )
        save_state(state_path, state)
        print(f"[PR7] dedup suppressed(exact): level={level} fingerprint={exact_fp} count={count} window={cooldown}s")
        return 0

    # same-class aggregation suppression (CRITICAL bypasses this by design)
    if level != "CRITICAL" and in_window(state["last_sent_class"].get(class_fp), now_ts, cooldown):
        count = update_group(state["groups"], class_fp, now_ts, args.aggregate_seconds)
        stats["alerts_suppressed"] += 1
        record_delivery(
            state,
            event="suppressed",
            reason=f"class_dedup_{cooldown}s",
            channel=primary_channel,
            report_status=report.get("status", "UNKNOWN"),
            fingerprint=class_fp,
            report_path=report_path,
        )
        save_state(state_path, state)
        print(f"[PR7] dedup suppressed(class): level={level} class={class_fp} count={count} cooldown={cooldown}s")
        return 0

    aggregate_count = update_group(state["groups"], class_fp, now_ts, args.aggregate_seconds)
    text = build_message(
        report,
        report_path,
        level,
        aggregate_count,
        args.aggregate_seconds,
        escalated_from_warn=escalated_from_warn,
        warn_streak_count=warn_streak_count,
        warn_escalate_count=warn_escalate_count,
    )

    planned_targets = route_targets(level, primary_channel, backup_channel)
    route_results: list[dict] = []
    success_channels: set[str] = set()

    def deliver_to_channel(ch: str, reason: str, simulate_failures: int) -> tuple[bool, int, str]:
        ok0, attempts0, err0 = send_with_retry(
            channel=ch,
            text=text,
            dry_run=args.dry_run,
            max_retries=max(0, args.max_retries),
            base_backoff_ms=max(1, args.base_backoff_ms),
            max_backoff_ms=max(1, args.max_backoff_ms),
            dry_run_simulate_failures=((simulate_failures if simulate_failures > 0 else (max(0, args.max_retries) + 1)) if (args.dry_run and ch in dry_run_fail_channels) else 0),
            global_retry_budget=max(0, args.global_retry_budget),
            global_retry_window_seconds=max(1, args.global_retry_window_seconds),
            global_retry_budget_state_file=args.global_retry_budget_state_file,
            retry_jitter_seed=args.retry_jitter_seed,
        )
        route_results.append(
            {
                "channel": ch,
                "reason": reason,
                "ok": ok0,
                "attempts": attempts0,
                "error": err0,
            }
        )
        append_audit(
            Path(args.audit_file),
            {
                "at_utc": now_iso,
                "fingerprint": exact_fp,
                "class_fingerprint": class_fp,
                "level": level,
                "report_path": str(report_path),
                "channel": ch,
                "reason": reason,
                "ok": ok0,
                "attempts": attempts0,
                "error": err0,
                "dry_run": args.dry_run,
            },
        )
        return ok0, attempts0, err0

    for target in planned_targets:
        ok0, _attempts0, _err0 = deliver_to_channel(target, "planned_route", max(0, args.dry_run_simulate_failures))
        if ok0:
            success_channels.add(target)

    primary_ok = any(r["channel"] == primary_channel and r["ok"] for r in route_results)
    if level != "CRITICAL" and (not primary_ok) and backup_channel and backup_channel != primary_channel and backup_channel not in planned_targets:
        ok0, _attempts0, _err0 = deliver_to_channel(backup_channel, "fallback_after_primary_failure", max(0, args.dry_run_simulate_failures))
        if ok0:
            success_channels.add(backup_channel)

    required_success = len(planned_targets)
    attempts = sum(int(r.get("attempts", 0) or 0) for r in route_results)
    failed_items = [r for r in route_results if not r.get("ok")]
    err = "; ".join(str(x.get("error", "")) for x in failed_items if x.get("error"))

    delivery_summary = {
        "at_utc": now_iso,
        "record_type": "delivery_summary",
        "fingerprint": exact_fp,
        "class_fingerprint": class_fp,
        "level": level,
        "report_path": str(report_path),
        "channels_total": len(route_results),
        "channels_ok": len(success_channels),
        "channels_failed": len([r for r in route_results if not r.get("ok")]),
        "attempts": attempts,
        "dry_run": args.dry_run,
    }

    if len(success_channels) == 0:
        dead_letter = {
            "created_at_utc": now_iso,
            "source": "pr7_alert_delivery",
            "channel": primary_channel,
            "report_path": str(report_path),
            "fingerprint": exact_fp,
            "class_fingerprint": class_fp,
            "level": level,
            "status": report.get("status", "UNKNOWN"),
            "message": text,
            "attempts": attempts,
            "max_retries": args.max_retries,
            "last_error": err,
            "dry_run": args.dry_run,
        }
        append_dead_letter(Path(args.dead_letter_file), dead_letter)
        stats["alerts_failed"] += 1
        record_delivery(
            state,
            event="failed",
            reason=err,
            channel=primary_channel,
            report_status=report.get("status", "UNKNOWN"),
            fingerprint=exact_fp,
            report_path=report_path,
        )
        append_audit(
            Path(args.audit_file),
            {
                **delivery_summary,
                "event": "failed",
                "ok": False,
                "reason": err,
                "primary_channel": primary_channel,
            },
        )
        save_state(state_path, state)
        print(
            f"[PR7][FAIL] notify delivery exhausted retries; dead-letter appended "
            f"file={args.dead_letter_file} fingerprint={exact_fp} attempts={attempts} err={err}",
            file=sys.stderr,
        )
        return 3

    partial_success = len(success_channels) < required_success

    stats["alerts_sent"] += 1
    state["last_sent"][exact_fp] = now_ts
    state["last_sent_exact"][exact_fp] = now_ts
    state["last_sent_class"][class_fp] = now_ts
    clear_group(state["groups"], class_fp, now_ts)
    if escalated_from_warn:
        clear_warn_streaks(state["warn_streaks"], mk_class_fingerprint(report, "WARN"), now_ts)
    delivery_event = "partial_success" if partial_success else "sent"
    delivery_reason = (
        "partial_success:" + ",".join(sorted(str(r.get("channel")) for r in failed_items if r.get("channel")))
        if partial_success
        else "ok"
    )
    record_delivery(
        state,
        event=delivery_event,
        reason=delivery_reason,
        channel=primary_channel,
        report_status=report.get("status", "UNKNOWN"),
        fingerprint=exact_fp,
        report_path=report_path,
    )
    append_audit(
        Path(args.audit_file),
        {
            **delivery_summary,
            "event": delivery_event,
            "ok": True,
            "reason": delivery_reason,
            "primary_channel": primary_channel,
        },
    )
    save_state(state_path, state)

    mode = "DRY_RUN" if args.dry_run else "LIVE"
    if partial_success:
        print(
            f"[PR7][WARN] partial_success mode={mode} level={level} primary={primary_channel} backup={backup_channel or '-'} "
            f"exact={exact_fp} class={class_fp} aggregate_count={aggregate_count} attempts={attempts} "
            f"failed_channels={[r.get('channel') for r in failed_items]} route_results={route_results}"
        )
        return 0
    print(
        f"[PR7] sent mode={mode} level={level} primary={primary_channel} backup={backup_channel or '-'} "
        f"exact={exact_fp} class={class_fp} aggregate_count={aggregate_count} attempts={attempts} "
        f"escalated_from_warn={escalated_from_warn} warn_streak={warn_streak_count} route_results={route_results}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
