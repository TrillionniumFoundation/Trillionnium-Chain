#!/usr/bin/env python3
"""Measure canonical finalized + replay-verified transaction goodput.

The input is newline-delimited JSON, one transaction telemetry record per line.
Only records on the canonical path with finality_status=finalized and
replay_verified=true contribute to finality latency and goodput.  Speculative
worker records are rejected instead of silently becoming a result claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

WORKLOADS = ("classic", "mixed", "hot-streak")
SEGMENTS = (
    "client_submit", "mempool_queue", "consensus", "scheduler_grouping",
    "execution", "commit", "storage", "finality_observation",
)
SCHEMA = "trnm_e2e_tx_event_v1"


def fail(message: str) -> None:
    raise SystemExit(f"VALIDATION_ERROR: {message}")


def parse_time(value: object, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        fail(f"{label} must be an RFC3339 UTC string or null")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        fail(f"{label} is not an RFC3339 timestamp: {value!r}")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail(f"{label} must include UTC timezone")
    return parsed.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    # Nearest-rank is deterministic and is the denominator used by this gate.
    rank = max(1, math.ceil(p * len(values)))
    return round(sorted(values)[rank - 1], 3)


def read_events(path: Path) -> tuple[list[dict], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    events: list[dict] = []
    seen: set[str] = set()
    for lineno, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"line {lineno}: invalid JSON ({exc.msg})")
        if not isinstance(event, dict):
            fail(f"line {lineno}: event must be an object")
        if event.get("schema") != SCHEMA:
            fail(f"line {lineno}: schema must be {SCHEMA}")
        tx_id = event.get("tx_id")
        if not isinstance(tx_id, str) or not tx_id:
            fail(f"line {lineno}: tx_id must be a non-empty string")
        if tx_id in seen:
            fail(f"line {lineno}: duplicate tx_id {tx_id!r}")
        seen.add(tx_id)
        workload = event.get("workload")
        if workload not in WORKLOADS:
            fail(f"line {lineno}: workload must be one of {WORKLOADS}")
        path_name = event.get("execution_path")
        if path_name != "canonical":
            fail(f"line {lineno}: execution_path must be canonical; speculative data is not a result")
        submitted = parse_time(event.get("submitted_at_utc"), f"line {lineno} submitted_at_utc")
        if submitted is None:
            fail(f"line {lineno}: submitted_at_utc is required")
        finalized = parse_time(event.get("finalized_at_utc"), f"line {lineno} finalized_at_utc")
        if finalized is not None and finalized < submitted:
            fail(f"line {lineno}: finalized_at_utc precedes submitted_at_utc")
        status = event.get("finality_status")
        if status not in {"pending", "finalized", "rejected"}:
            fail(f"line {lineno}: finality_status must be pending/finalized/rejected")
        if status == "finalized" and finalized is None:
            fail(f"line {lineno}: finalized record needs finalized_at_utc")
        if status != "finalized" and finalized is not None:
            fail(f"line {lineno}: only finalized records may set finalized_at_utc")
        replay = event.get("replay_verified")
        if not isinstance(replay, bool):
            fail(f"line {lineno}: replay_verified must be boolean")
        if replay and status != "finalized":
            fail(f"line {lineno}: replay_verified requires finality_status=finalized")
        retry_count = event.get("retry_count", 0)
        if not isinstance(retry_count, int) or retry_count < 0:
            fail(f"line {lineno}: retry_count must be a non-negative integer")
        rollback = event.get("rollback", False)
        if not isinstance(rollback, bool):
            fail(f"line {lineno}: rollback must be boolean")
        segments = event.get("segment_latency_ms", {})
        if not isinstance(segments, dict):
            fail(f"line {lineno}: segment_latency_ms must be an object")
        clean_segments = {}
        for segment, value in segments.items():
            if segment not in SEGMENTS:
                fail(f"line {lineno}: unknown segment {segment!r}")
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                fail(f"line {lineno}: segment {segment} must be a non-negative number")
            clean_segments[segment] = float(value)
        event = dict(event)
        event["_submitted"] = submitted
        event["_finalized"] = finalized
        event["_segments"] = clean_segments
        events.append(event)
    if not events:
        fail("input contains no telemetry events")
    return events, digest


def measure(events: list[dict], digest: str, source: Path) -> dict:
    submitted_times = [e["_submitted"] for e in events]
    verified = [e for e in events if e["finality_status"] == "finalized" and e["replay_verified"]]
    finalized = [e for e in events if e["finality_status"] == "finalized"]
    if not verified:
        fail("no finalized + replay-verified transaction; refusing to claim goodput")
    first_submit = min(submitted_times)
    last_finalized = max(e["_finalized"] for e in verified)
    elapsed = (last_finalized - first_submit).total_seconds()
    if elapsed <= 0:
        fail("measurement window must be positive")
    latency_ms = [
        (e["_finalized"] - e["_submitted"]).total_seconds() * 1000.0 for e in verified
    ]
    tx_count = len(events)
    finalized_count = len(verified)
    segment_values: dict[str, list[float]] = defaultdict(list)
    for event in verified:
        for segment, value in event["_segments"].items():
            segment_values[segment].append(value)
    segment_avg = {segment: round(mean(segment_values[segment]), 3) if segment_values[segment] else None for segment in SEGMENTS}
    bottleneck = max((s for s in SEGMENTS if segment_avg[s] is not None), key=lambda s: segment_avg[s], default=None)
    workloads = {}
    for workload in WORKLOADS:
        subset = [e for e in events if e["workload"] == workload]
        good = [e for e in verified if e["workload"] == workload]
        wl_lat = [(e["_finalized"] - e["_submitted"]).total_seconds() * 1000.0 for e in good]
        wl_duration = ((max((e["_finalized"] for e in good), default=first_submit) -
                        min((e["_submitted"] for e in subset), default=first_submit)).total_seconds())
        workloads[workload] = {
            "submitted": len(subset),
            "finalized": len([e for e in subset if e["finality_status"] == "finalized"]),
            "replay_verified_finalized": len(good),
            "duration_ms": round(wl_duration * 1000.0, 3) if good else None,
            "finalized_goodput_tps": round(len(good) / wl_duration, 6) if good and wl_duration > 0 else 0.0,
            "finality_p50_ms": percentile(wl_lat, 0.50),
            "finality_p95_ms": percentile(wl_lat, 0.95),
            "finality_p99_ms": percentile(wl_lat, 0.99),
        }
    return {
        "schema": "trnm_finalized_goodput_measurement_v1",
        "generated_at_utc": iso(datetime.now(timezone.utc)),
        "status": "complete",
        "measurement_policy": {
            "included": "canonical records with finality_status=finalized and replay_verified=true",
            "excluded": "pending, rejected, non-replay-verified, and all speculative-worker records",
            "percentile": "nearest-rank; rank=ceil(p*n)",
            "goodput_denominator": "last replay-verified finalization minus first submission",
        },
        "source": {"path": str(source), "sha256": digest, "event_count": tx_count},
        "window": {
            "submit_window_started_at_utc": iso(first_submit),
            "finality_observed_at_utc": iso(last_finalized),
            "duration_ms": round(elapsed * 1000.0, 3),
        },
        "counts": {
            "submitted": tx_count,
            "finalized": len(finalized),
            "replay_verified_finalized": finalized_count,
            "excluded_unfinalized_or_rejected": tx_count - len(finalized),
            "excluded_not_replay_verified": len(finalized) - finalized_count,
            "speculative_rejected": 0,
        },
        "metrics": {
            "submit_tps": round(tx_count / elapsed, 6),
            "finalized_goodput_tps": round(finalized_count / elapsed, 6),
            "finality_p50_ms": percentile(latency_ms, 0.50),
            "finality_p95_ms": percentile(latency_ms, 0.95),
            "finality_p99_ms": percentile(latency_ms, 0.99),
            "drop_rate": round(1.0 - finalized_count / tx_count, 6),
            "retry_rate": round(sum(e["retry_count"] > 0 for e in events) / tx_count, 6),
            "rollback_rate": round(sum(e["rollback"] for e in events) / tx_count, 6),
        },
        "segment_latency_ms_avg": segment_avg,
        "bottleneck_segment": bottleneck,
        "workloads": workloads,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure finalized, replay-verified TRNM goodput from JSONL telemetry")
    parser.add_argument("input", type=Path, help="newline-delimited trnm_e2e_tx_event_v1 telemetry")
    parser.add_argument("-o", "--output", type=Path, help="write measurement JSON here (default: stdout)")
    args = parser.parse_args()
    events, digest = read_events(args.input)
    result = measure(events, digest, args.input)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
