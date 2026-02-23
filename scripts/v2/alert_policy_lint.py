#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

LEVELS = {"INFO", "WARN", "CRITICAL"}
CHANNELS = {"slack", "telegram", "imessage"}
HHMM_RE = re.compile(r"^[0-2][0-9]:[0-5][0-9]$")


def req(obj: dict, key: str, path: str):
    if key not in obj:
        raise ValueError(f"missing {path}.{key}")
    return obj[key]


def ensure_int(v, path: str, minv: int = 0):
    if not isinstance(v, int):
        raise ValueError(f"{path} must be int")
    if v < minv:
        raise ValueError(f"{path} must be >= {minv}")


def ensure_num(v, path: str, minv: float = 0.0):
    if not isinstance(v, (int, float)):
        raise ValueError(f"{path} must be number")
    if float(v) < minv:
        raise ValueError(f"{path} must be >= {minv}")


def lint_profile(name: str, p: dict) -> None:
    t = req(p, "thresholds", f"profiles.{name}")
    for k in ("unresolved_challenges", "forfeits_daily_increase"):
        node = req(t, k, f"profiles.{name}.thresholds")
        warn = req(node, "warn", f"profiles.{name}.thresholds.{k}")
        fail = req(node, "fail", f"profiles.{name}.thresholds.{k}")
        ensure_int(warn, f"profiles.{name}.thresholds.{k}.warn")
        ensure_int(fail, f"profiles.{name}.thresholds.{k}.fail")
        if warn > fail:
            raise ValueError(f"profiles.{name}.thresholds.{k}.warn cannot be greater than fail")

    k = "escrow_nonzero_hours"
    node = req(t, k, f"profiles.{name}.thresholds")
    warn = req(node, "warn", f"profiles.{name}.thresholds.{k}")
    fail = req(node, "fail", f"profiles.{name}.thresholds.{k}")
    ensure_num(warn, f"profiles.{name}.thresholds.{k}.warn")
    ensure_num(fail, f"profiles.{name}.thresholds.{k}.fail")
    if float(warn) > float(fail):
        raise ValueError(f"profiles.{name}.thresholds.{k}.warn cannot be greater than fail")

    d = req(p, "delivery", f"profiles.{name}")
    min_level = req(d, "min_level", f"profiles.{name}.delivery")
    if min_level not in LEVELS:
        raise ValueError(f"profiles.{name}.delivery.min_level invalid: {min_level}")

    route = req(d, "channel_route", f"profiles.{name}.delivery")
    for level in ("info", "warn", "critical"):
        ch = req(route, level, f"profiles.{name}.delivery.channel_route")
        if ch not in CHANNELS:
            raise ValueError(f"profiles.{name}.delivery.channel_route.{level} invalid: {ch}")

    ensure_int(req(d, "dedup_seconds", f"profiles.{name}.delivery"), f"profiles.{name}.delivery.dedup_seconds")
    ensure_int(req(d, "aggregate_seconds", f"profiles.{name}.delivery"), f"profiles.{name}.delivery.aggregate_seconds")

    retries = req(d, "retries", f"profiles.{name}.delivery")
    ensure_int(req(retries, "max_retries", f"profiles.{name}.delivery.retries"), f"profiles.{name}.delivery.retries.max_retries")
    ensure_int(req(retries, "base_backoff_ms", f"profiles.{name}.delivery.retries"), f"profiles.{name}.delivery.retries.base_backoff_ms")
    ensure_int(req(retries, "max_backoff_ms", f"profiles.{name}.delivery.retries"), f"profiles.{name}.delivery.retries.max_backoff_ms")

    cooldown = req(d, "cooldown", f"profiles.{name}.delivery")
    for level in ("info", "warn", "critical"):
        ensure_int(req(cooldown, level, f"profiles.{name}.delivery.cooldown"), f"profiles.{name}.delivery.cooldown.{level}")

    qh = req(d, "quiet_hours", f"profiles.{name}.delivery")
    if not isinstance(req(qh, "enabled", f"profiles.{name}.delivery.quiet_hours"), bool):
        raise ValueError(f"profiles.{name}.delivery.quiet_hours.enabled must be bool")
    if not isinstance(req(qh, "critical_bypass", f"profiles.{name}.delivery.quiet_hours"), bool):
        raise ValueError(f"profiles.{name}.delivery.quiet_hours.critical_bypass must be bool")
    for key in ("start", "end"):
        v = req(qh, key, f"profiles.{name}.delivery.quiet_hours")
        if not isinstance(v, str) or not HHMM_RE.match(v):
            raise ValueError(f"profiles.{name}.delivery.quiet_hours.{key} must match HH:MM")
    tz = req(qh, "tz", f"profiles.{name}.delivery.quiet_hours")
    if not isinstance(tz, str) or not tz.strip():
        raise ValueError(f"profiles.{name}.delivery.quiet_hours.tz must be non-empty string")

    esc = req(d, "escalation", f"profiles.{name}.delivery")
    ensure_int(req(esc, "warn_escalate_count", f"profiles.{name}.delivery.escalation"), f"profiles.{name}.delivery.escalation.warn_escalate_count")
    ensure_int(req(esc, "warn_escalate_window_seconds", f"profiles.{name}.delivery.escalation"), f"profiles.{name}.delivery.escalation.warn_escalate_window_seconds", minv=1)


def main() -> int:
    ap = argparse.ArgumentParser(description="Lint alert policy config")
    ap.add_argument("--policy", default="config/alert-policy/current.json")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[2]
    policy_path = (root / args.policy).resolve() if not Path(args.policy).is_absolute() else Path(args.policy)
    data = json.loads(policy_path.read_text(encoding="utf-8"))

    if data.get("schema_version") != "1.0":
        raise SystemExit("schema_version must be 1.0")
    for key in ("policy_id", "version", "profiles"):
        if key not in data:
            raise SystemExit(f"missing top-level field: {key}")
    if not isinstance(data["profiles"], dict) or not data["profiles"]:
        raise SystemExit("profiles must be non-empty object")

    for name, profile in data["profiles"].items():
        if not isinstance(profile, dict):
            raise SystemExit(f"profiles.{name} must be object")
        lint_profile(name, profile)

    print(f"OK policy={policy_path} profiles={','.join(sorted(data['profiles'].keys()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
