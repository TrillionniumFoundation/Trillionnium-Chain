#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

KV_RE = re.compile(r"(\w+)=([^\s]+)")


def parse_event_log(path: Path) -> dict:
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.startswith("[event]"):
                continue
            kv = dict(KV_RE.findall(line))
            if kv.get("event_type") not in {"challenge", "resolve"}:
                continue
            rows.append(
                {
                    "event_type": kv.get("event_type", ""),
                    "task_id": kv.get("task_id", ""),
                    "tx_hash": kv.get("tx_hash", ""),
                    "treasury_delta": int(kv.get("treasury_delta", "0")) if kv.get("treasury_delta", "0").lstrip("-").isdigit() else 0,
                    "challenger_delta": int(kv.get("challenger_delta", "0")) if kv.get("challenger_delta", "0").lstrip("-").isdigit() else 0,
                    "bond_disposition": kv.get("bond_disposition", ""),
                }
            )
    return {
        "rows": rows,
        "challenge_count": sum(1 for r in rows if r["event_type"] == "challenge"),
        "resolve_count": sum(1 for r in rows if r["event_type"] == "resolve"),
        "forfeited_total": sum(-r["challenger_delta"] for r in rows if r["event_type"] == "challenge" and r["bond_disposition"] == "posted" and r["challenger_delta"] < 0)
        - sum(r["challenger_delta"] for r in rows if r["event_type"] == "resolve" and r["bond_disposition"] == "refunded" and r["challenger_delta"] > 0),
    }


def parse_summary(path: Path) -> dict:
    out = {}
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            if "=" not in raw:
                continue
            k, v = raw.strip().split("=", 1)
            out[k] = v
    return out


def parse_rpc_treasury(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    events = payload.get("events", []) if isinstance(payload, dict) else []
    anomalies = payload.get("anomalies", []) if isinstance(payload, dict) else []
    anomaly_codes = [str(a.get("code", "")) for a in anomalies if isinstance(a, dict)]
    return {
        "payload": payload,
        "events": events,
        "challenge_count": sum(1 for e in events if e.get("event_type") == "challenge"),
        "resolve_count": sum(1 for e in events if e.get("event_type") == "resolve"),
        "forfeits_balance": int(payload.get("current_forfeits_balance", 0)),
        "cumulative_forfeited": int(payload.get("cumulative_forfeited", 0)),
        "anomaly_count": int(payload.get("anomaly_count", len(anomalies)) or 0),
        "anomaly_codes": anomaly_codes,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="PR5 triad consistency check: event log / PR5 report / RPC treasury")
    ap.add_argument("--event-log", required=True)
    ap.add_argument("--pr5-summary", required=True)
    ap.add_argument("--rpc-treasury-json", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    ev = parse_event_log(Path(args.event_log))
    pr5 = parse_summary(Path(args.pr5_summary))
    rpc = parse_rpc_treasury(Path(args.rpc_treasury_json))

    details = []
    status = "PASS"
    known_anomaly_codes = {"duplicate_event_replay", "resolve_without_posted_bond"}

    if pr5.get("status") != "PASS":
        details.append(f"pr5 summary not PASS: status={pr5.get('status')}")
    if pr5.get("conservation.gap") not in {"0", "0.0"}:
        details.append(f"pr5 conservation gap !=0: {pr5.get('conservation.gap')}")

    pr5_record_count = int(pr5.get("record_count", "0") or 0)
    if pr5_record_count != len(ev["rows"]):
        details.append(f"event/pr5 record_count mismatch: event={len(ev['rows'])} pr5={pr5_record_count}")

    if rpc["challenge_count"] < ev["challenge_count"] or rpc["resolve_count"] < ev["resolve_count"]:
        details.append(
            f"rpc treasury events incomplete: rpc_challenge={rpc['challenge_count']} rpc_resolve={rpc['resolve_count']} "
            f"event_challenge={ev['challenge_count']} event_resolve={ev['resolve_count']}"
        )

    if rpc["cumulative_forfeited"] < ev["forfeited_total"]:
        details.append(
            "rpc cumulative_forfeited below event-derived forfeited_total: "
            f"rpc={rpc['cumulative_forfeited']} event={ev['forfeited_total']} "
            f"(note: current_forfeits_balance is a stock value and may be lower after burns/spends)"
        )

    unknown_anomaly_codes = sorted({c for c in rpc["anomaly_codes"] if c and c not in known_anomaly_codes})
    if unknown_anomaly_codes:
        details.append(
            "rpc anomaly contains unknown code(s): " + ",".join(unknown_anomaly_codes)
        )
    elif rpc["anomaly_count"] > 0:
        details.append(
            "rpc anomaly observed with known code(s): " + ",".join(sorted(set(rpc["anomaly_codes"])) or ["(missing-code)"])
        )

    if details:
        fail_keywords = (
            "not PASS",
            "gap !=0",
            "mismatch",
            "incomplete",
            "below event-derived",
            "unknown code",
        )
        if any(any(k in d for k in fail_keywords) for d in details):
            status = "FAIL"

    report_lines = [
        f"status={status}",
        f"event_log={args.event_log}",
        f"pr5_summary={args.pr5_summary}",
        f"rpc_treasury_json={args.rpc_treasury_json}",
        f"event.record_count={len(ev['rows'])}",
        f"pr5.record_count={pr5_record_count}",
        f"event.challenge_count={ev['challenge_count']}",
        f"event.resolve_count={ev['resolve_count']}",
        f"rpc.challenge_count={rpc['challenge_count']}",
        f"rpc.resolve_count={rpc['resolve_count']}",
        f"event.forfeited_total={ev['forfeited_total']}",
        f"rpc.cumulative_forfeited={rpc['cumulative_forfeited']}",
        f"rpc.current_forfeits_balance={rpc['forfeits_balance']}",
        f"rpc.anomaly_count={rpc['anomaly_count']}",
        f"rpc.anomaly_codes={','.join(rpc['anomaly_codes'])}",
        f"detail_count={len(details)}",
    ]
    report_lines.extend(f"detail.{i+1}={d}" for i, d in enumerate(details))

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"[PR5][triad] status={status} report={out}")
    if details:
        for d in details[:10]:
            print(f"  - {d}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())