#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def read_policy(path: Path, profile: str) -> tuple[dict, dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    profiles = doc.get("profiles") or {}
    if profile not in profiles:
        raise SystemExit(f"profile not found: {profile}; available={','.join(sorted(profiles.keys()))}")
    return doc, profiles[profile]


def as_env(doc: dict, profile_name: str, profile: dict) -> dict[str, str]:
    t = profile["thresholds"]
    d = profile["delivery"]
    qh = d["quiet_hours"]
    esc = d["escalation"]
    retries = d["retries"]
    cooldown = d["cooldown"]
    route = d["channel_route"]

    return {
        "ALERT_POLICY_ID": str(doc.get("policy_id", "")),
        "ALERT_POLICY_VERSION": str(doc.get("version", "")),
        "ALERT_POLICY_PROFILE": profile_name,
        "WARN_UNRESOLVED_CHALLENGES": str(int(t["unresolved_challenges"]["warn"])),
        "FAIL_UNRESOLVED_CHALLENGES": str(int(t["unresolved_challenges"]["fail"])),
        "WARN_FORFEITS_DAILY_INCREASE": str(int(t["forfeits_daily_increase"]["warn"])),
        "FAIL_FORFEITS_DAILY_INCREASE": str(int(t["forfeits_daily_increase"]["fail"])),
        "WARN_ESCROW_NONZERO_HOURS": f"{float(t['escrow_nonzero_hours']['warn']):.2f}",
        "FAIL_ESCROW_NONZERO_HOURS": f"{float(t['escrow_nonzero_hours']['fail']):.2f}",
        "ALERT_NOTIFY_MIN_LEVEL": str(d["min_level"]),
        "ALERT_NOTIFY_CHANNEL_INFO": str(route["info"]),
        "ALERT_NOTIFY_CHANNEL_WARN": str(route["warn"]),
        "ALERT_NOTIFY_CHANNEL_CRITICAL": str(route["critical"]),
        "ALERT_NOTIFY_DEDUP_SECONDS": str(int(d["dedup_seconds"])),
        "ALERT_NOTIFY_AGGREGATE_SECONDS": str(int(d["aggregate_seconds"])),
        "ALERT_NOTIFY_MAX_RETRIES": str(int(retries["max_retries"])),
        "ALERT_NOTIFY_BASE_BACKOFF_MS": str(int(retries["base_backoff_ms"])),
        "ALERT_NOTIFY_MAX_BACKOFF_MS": str(int(retries["max_backoff_ms"])),
        "ALERT_NOTIFY_COOLDOWN_INFO": str(int(cooldown["info"])),
        "ALERT_NOTIFY_COOLDOWN_WARN": str(int(cooldown["warn"])),
        "ALERT_NOTIFY_COOLDOWN_CRITICAL": str(int(cooldown["critical"])),
        "ALERT_NOTIFY_QUIET_HOURS_ENABLED": "1" if bool(qh["enabled"]) else "0",
        "ALERT_NOTIFY_QUIET_HOURS_START": str(qh["start"]),
        "ALERT_NOTIFY_QUIET_HOURS_END": str(qh["end"]),
        "ALERT_NOTIFY_QUIET_HOURS_TZ": str(qh["tz"]),
        "ALERT_NOTIFY_WARN_ESCALATE_COUNT": str(int(esc["warn_escalate_count"])),
        "ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS": str(int(esc["warn_escalate_window_seconds"])),
    }


def maybe_audit(root: Path, policy_path: Path, env_rows: dict[str, str], *, enabled: bool) -> None:
    if not enabled:
        return
    hist_dir = root / "run/pr9/policy-history"
    hist_dir.mkdir(parents=True, exist_ok=True)
    changelog = root / "run/pr9/policy-changelog.md"

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    version = env_rows.get("ALERT_POLICY_VERSION", "unknown")
    snap = hist_dir / f"{ts}-{version}.json"
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "policy_file": str(policy_path),
        "policy_id": env_rows.get("ALERT_POLICY_ID", ""),
        "policy_version": version,
        "profile": env_rows.get("ALERT_POLICY_PROFILE", ""),
        "resolved_env": env_rows,
    }
    snap.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if not changelog.exists():
        changelog.write_text("# PR9 Alert Policy Changelog\n\n", encoding="utf-8")
    with changelog.open("a", encoding="utf-8") as f:
        f.write(f"- {payload['generated_at_utc']} | version={version} | profile={payload['profile']} | snapshot={snap}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Resolve policy JSON to env file for PR6/PR7/PR9")
    ap.add_argument("--policy", default="config/alert-policy/current.json")
    ap.add_argument("--profile", default=os.environ.get("ALERT_POLICY_PROFILE", "default"))
    ap.add_argument("--out-env", required=True)
    ap.add_argument("--only-missing", action="store_true", default=False)
    ap.add_argument("--audit", action="store_true", default=False)
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[2]
    policy_path = (root / args.policy).resolve() if not Path(args.policy).is_absolute() else Path(args.policy)
    doc, profile = read_policy(policy_path, args.profile)
    env_rows = as_env(doc, args.profile, profile)

    final_rows = {}
    for k, v in env_rows.items():
        if args.only_missing and os.environ.get(k):
            continue
        final_rows[k] = v

    out = Path(args.out_env)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# generated from {policy_path}"]
    lines.extend(f"{k}={v}" for k, v in final_rows.items())
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    maybe_audit(root, policy_path, env_rows, enabled=args.audit)
    print(f"WROTE {out} vars={len(final_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
