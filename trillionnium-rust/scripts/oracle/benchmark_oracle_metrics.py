#!/usr/bin/env python3
import argparse
import json
import random
import statistics
import time
from pathlib import Path


def median(vals):
    if not vals:
        return None
    vals = sorted(vals)
    n = len(vals)
    m = n // 2
    return (vals[m - 1] + vals[m]) / 2 if n % 2 == 0 else vals[m]


def validate_snapshot(s, min_sources, max_staleness_ms, max_deviation_bps):
    now_ms = int(s.get("snapshot_ts_ms", 0))
    latest_sample_by_source = {}
    for src in s.get("sources", []):
        sid = src.get("source", "").strip().lower()
        if not sid:
            continue
        ts = int(src.get("ts_unix_ms", now_ms))
        current = latest_sample_by_source.get(sid)
        if current is None or ts >= current[0]:
            latest_sample_by_source[sid] = (ts, float(src.get("value", 0.0)))

    for ts, _value in latest_sample_by_source.values():
        age_ms = now_ms - ts
        if age_ms < 0 or age_ms > max_staleness_ms:
            return "stale", len(latest_sample_by_source)

    if len(latest_sample_by_source) < min_sources:
        return "quorum", len(latest_sample_by_source)

    values = [value for _ts, value in latest_sample_by_source.values()]
    m = median(values)
    if m is None:
        return "quorum", len(latest_sample_by_source)

    if abs(m) <= 1e-12:
        if any(abs(v - m) > 1e-12 for v in values):
            return "drift", len(latest_sample_by_source)
        return "ok", len(latest_sample_by_source)

    lim = abs(m) * (max_deviation_bps / 10000.0)
    for v in values:
        if abs(v - m) >= lim:
            return "drift", len(latest_sample_by_source)

    return "ok", len(latest_sample_by_source)


def run_baseline(cases, args):
    t0 = time.perf_counter_ns()
    stale = quorum = drift = 0
    accepted_source_cardinalities = []
    oks = 0
    for s in cases:
        r, card = validate_snapshot(s, args.min_sources, args.max_staleness_ms, args.max_deviation_bps)
        if r == "stale":
            stale += 1
        elif r == "quorum":
            quorum += 1
        elif r == "drift":
            drift += 1
        else:
            oks += 1
            accepted_source_cardinalities.append(card)
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    source_cardinality = max(accepted_source_cardinalities, default=0)
    return {
        "oracle_ingest_latency_ms": round(elapsed_ms, 3),
        "oracle_stale_reject_total": stale,
        "oracle_quorum_reject_total": quorum,
        "oracle_drift_reject_total": drift,
        "oracle_source_cardinality": source_cardinality,
        "accepted_total": oks,
        "sample_count": len(cases),
    }


def synth_case(ts):
    base = 1.0 + random.uniform(-0.002, 0.002)
    return {
        "feed_id": "trnm/usdt",
        "snapshot_ts_ms": ts,
        "sources": [
            {"source": "s1", "value": base, "ts_unix_ms": ts},
            {"source": "s2", "value": base * (1 + random.uniform(-0.001, 0.001)), "ts_unix_ms": ts - random.randint(0, 1200)},
            {"source": "s3", "value": base * (1 + random.uniform(-0.001, 0.001)), "ts_unix_ms": ts - random.randint(0, 1200)},
        ],
    }


def _require_positive(name, value):
    if value <= 0:
        raise SystemExit(f"{name} must be > 0")



def run_bench(args):
    _require_positive("bench_count", args.bench_count)
    _require_positive("bench_rounds", args.bench_rounds)

    lat = []
    now = int(time.time() * 1000)
    for i in range(args.bench_rounds):
        cases = [synth_case(now + i * 1000 + j) for j in range(args.bench_count)]
        out = run_baseline(cases, args)
        lat.append(out["oracle_ingest_latency_ms"])
    lat_sorted = sorted(lat)
    p50 = statistics.median(lat_sorted)
    p95 = lat_sorted[min(len(lat_sorted) - 1, int(len(lat_sorted) * 0.95))]
    return {
        "bench_rounds": args.bench_rounds,
        "bench_count": args.bench_count,
        "ingest_latency_p50_ms": round(p50, 3),
        "ingest_latency_p95_ms": round(p95, 3),
        "ingest_latency_max_ms": round(max(lat_sorted), 3),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path)
    ap.add_argument("--min-sources", type=int, default=2)
    ap.add_argument("--max-staleness-ms", type=int, default=60_000)
    ap.add_argument("--max-deviation-bps", type=int, default=1_000)
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--bench-count", type=int, default=500)
    ap.add_argument("--bench-rounds", type=int, default=20)
    args = ap.parse_args()

    if args.bench:
        print(json.dumps(run_bench(args), ensure_ascii=False, indent=2))
        return

    if not args.input:
        raise SystemExit("--input is required when not in --bench mode")
    cases = json.loads(args.input.read_text())
    print(json.dumps(run_baseline(cases, args), ensure_ascii=False, indent=2))




def _test_deviation_equal_to_threshold_rejects_as_drift():
    status, cardinality = validate_snapshot(
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 95.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 105.0, "ts_unix_ms": 1_000},
            ],
        },
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    assert status == "drift"
    assert cardinality == 2


def _test_zero_median_still_rejects_drift():
    status, cardinality = validate_snapshot(
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 0.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 1.0, "ts_unix_ms": 1_000},
            ],
        },
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    assert status == "drift"
    assert cardinality == 2


def _test_future_dated_source_rejects_as_stale():
    status, cardinality = validate_snapshot(
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 1.0, "ts_unix_ms": 1_001},
                {"source": "s2", "value": 1.0, "ts_unix_ms": 1_000},
            ],
        },
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    assert status == "stale"
    assert cardinality == 2


def _test_duplicate_sources_count_once_for_quorum_and_drift():
    status, cardinality = validate_snapshot(
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
            ],
        },
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    assert status == "ok"
    assert cardinality == 2


def _test_duplicate_source_uses_latest_sample_for_staleness_and_drift():
    status, cardinality = validate_snapshot(
        {
            "snapshot_ts_ms": 10_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 10_000 - 61_000},
                {"source": "s1", "value": 100.0, "ts_unix_ms": 10_000},
                {"source": "s2", "value": 100.2, "ts_unix_ms": 10_000},
            ],
        },
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    assert status == "ok"
    assert cardinality == 2


def _test_duplicate_source_ids_canonicalize_before_dedup_and_quorum():
    status, cardinality = validate_snapshot(
        {
            "snapshot_ts_ms": 10_000,
            "sources": [
                {"source": " S1 ", "value": 100.0, "ts_unix_ms": 9_000},
                {"source": "s1", "value": 100.0, "ts_unix_ms": 10_000},
                {"source": " S2", "value": 100.2, "ts_unix_ms": 10_000},
            ],
        },
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    assert status == "ok"
    assert cardinality == 2


def _test_run_baseline_preserves_sample_accounting_contract():
    cases = [
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
            ],
        },
        {
            "snapshot_ts_ms": 2_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 2_000},
            ],
        },
        {
            "snapshot_ts_ms": 3_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 3_000},
                {"source": "s2", "value": 120.0, "ts_unix_ms": 3_000},
            ],
        },
        {
            "snapshot_ts_ms": 4_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 4_000 - 60_001},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 4_000},
            ],
        },
    ]

    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500

    out = run_baseline(cases, Args())
    rejected_total = (
        out["oracle_stale_reject_total"]
        + out["oracle_quorum_reject_total"]
        + out["oracle_drift_reject_total"]
    )
    assert out["accepted_total"] == 1
    assert rejected_total == 3
    assert out["sample_count"] == 4
    assert out["accepted_total"] + rejected_total == out["sample_count"]


def _test_run_baseline_keeps_max_accepted_source_cardinality():
    cases = [
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s3", "value": 100.0, "ts_unix_ms": 1_000},
            ],
        },
        {
            "snapshot_ts_ms": 2_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 2_000},
            ],
        },
    ]

    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500

    out = run_baseline(cases, Args())
    assert out["accepted_total"] == 2
    assert out["oracle_source_cardinality"] == 3
    assert out["sample_count"] == 2


def _test_run_baseline_ignores_rejected_higher_cardinality_when_reporting_accepted_max():
    cases = [
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
            ],
        },
        {
            "snapshot_ts_ms": 2_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "s3", "value": 130.0, "ts_unix_ms": 2_000},
                {"source": "s4", "value": 100.0, "ts_unix_ms": 2_000},
            ],
        },
    ]

    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500

    out = run_baseline(cases, Args())
    assert out["accepted_total"] == 1
    assert out["oracle_drift_reject_total"] == 1
    assert out["oracle_source_cardinality"] == 2
    assert out["sample_count"] == 2


def _test_run_baseline_zeros_source_cardinality_when_no_sample_is_accepted():
    cases = [
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
            ],
        },
        {
            "snapshot_ts_ms": 2_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "s2", "value": 130.0, "ts_unix_ms": 2_000},
            ],
        },
    ]

    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500

    out = run_baseline(cases, Args())
    assert out["accepted_total"] == 0
    assert out["oracle_source_cardinality"] == 0
    assert out["sample_count"] == 2



def _test_run_baseline_rejected_canonicalized_duplicates_do_not_inflate_accepted_aggregate_cardinality():
    cases = [
        {
            "snapshot_ts_ms": 1_000,
            "sources": [
                {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
            ],
        },
        {
            "snapshot_ts_ms": 2_000,
            "sources": [
                {"source": " S1 ", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "s1", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "S2", "value": 100.0, "ts_unix_ms": 2_000},
                {"source": "s3", "value": 130.0, "ts_unix_ms": 2_000},
            ],
        },
    ]

    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500

    out = run_baseline(cases, Args())
    assert out["accepted_total"] == 1
    assert out["oracle_drift_reject_total"] == 1
    assert out["oracle_source_cardinality"] == 2
    assert out["sample_count"] == 2



def _test_run_bench_rejects_zero_count_and_rounds_with_stable_error():
    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500
        bench_count = 0
        bench_rounds = 1

    try:
        run_bench(Args())
        raise AssertionError("zero bench_count should fail closed")
    except SystemExit as exc:
        assert str(exc) == "bench_count must be > 0"

    Args.bench_count = 1
    Args.bench_rounds = 0
    try:
        run_bench(Args())
        raise AssertionError("zero bench_rounds should fail closed")
    except SystemExit as exc:
        assert str(exc) == "bench_rounds must be > 0"


def _test_run_bench_reports_ordered_non_negative_latency_percentiles():
    class Args:
        min_sources = 2
        max_staleness_ms = 60_000
        max_deviation_bps = 500
        bench_count = 8
        bench_rounds = 4

    out = run_bench(Args())
    assert out["bench_count"] == 8
    assert out["bench_rounds"] == 4
    assert out["ingest_latency_p50_ms"] >= 0.0
    assert out["ingest_latency_p50_ms"] <= out["ingest_latency_p95_ms"]
    assert out["ingest_latency_p95_ms"] <= out["ingest_latency_max_ms"]


if __name__ == "__main__":
    main()
