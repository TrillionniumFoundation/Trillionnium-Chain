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


def _validate_baseline_output_contract(out):
    required = {
        "oracle_ingest_latency_ms",
        "oracle_stale_reject_total",
        "oracle_quorum_reject_total",
        "oracle_drift_reject_total",
        "oracle_source_cardinality",
        "accepted_total",
        "sample_count",
    }
    missing = sorted(required - out.keys())
    if missing:
        raise SystemExit(f"baseline contract missing keys: {missing}")

    rejected_total = (
        out["oracle_stale_reject_total"]
        + out["oracle_quorum_reject_total"]
        + out["oracle_drift_reject_total"]
    )
    if out["accepted_total"] + rejected_total != out["sample_count"]:
        raise SystemExit(
            "baseline contract violated: accepted_total + rejected_total must equal sample_count"
        )

    if out["accepted_total"] == 0 and out["oracle_source_cardinality"] != 0:
        raise SystemExit(
            "baseline contract violated: oracle_source_cardinality must be 0 when accepted_total is 0"
        )

    if out["accepted_total"] > 0 and out["oracle_source_cardinality"] == 0:
        raise SystemExit(
            "baseline contract violated: oracle_source_cardinality must be positive when accepted_total is non-zero"
        )


def _validate_bench_output_contract(out):
    required = {
        "bench_rounds",
        "bench_count",
        "ingest_latency_p50_ms",
        "ingest_latency_p95_ms",
        "ingest_latency_max_ms",
    }
    missing = sorted(required - out.keys())
    if missing:
        raise SystemExit(f"bench contract missing keys: {missing}")

    if not (
        out["ingest_latency_p50_ms"]
        <= out["ingest_latency_p95_ms"]
        <= out["ingest_latency_max_ms"]
    ):
        raise SystemExit(
            "bench contract violated: latency ordering must satisfy p50 <= p95 <= max"
        )


def run_baseline(cases, args):
    _validate_contract_args(args)
    if not cases:
        raise SystemExit("baseline input must contain at least one case")

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
    out = {
        "oracle_ingest_latency_ms": round(elapsed_ms, 3),
        "oracle_stale_reject_total": stale,
        "oracle_quorum_reject_total": quorum,
        "oracle_drift_reject_total": drift,
        "oracle_source_cardinality": source_cardinality,
        "accepted_total": oks,
        "sample_count": len(cases),
    }
    _validate_baseline_output_contract(out)
    return out


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


def _validate_contract_args(args):
    _require_positive("min_sources", args.min_sources)
    _require_positive("max_staleness_ms", args.max_staleness_ms)
    if args.max_deviation_bps < 0 or args.max_deviation_bps > 10_000:
        raise SystemExit("max_deviation_bps must be between 0 and 10000")



def run_bench(args):
    _validate_contract_args(args)
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
    out = {
        "bench_rounds": args.bench_rounds,
        "bench_count": args.bench_count,
        "ingest_latency_p50_ms": round(p50, 3),
        "ingest_latency_p95_ms": round(p95, 3),
        "ingest_latency_max_ms": round(max(lat_sorted), 3),
    }
    _validate_bench_output_contract(out)
    return out


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

    _validate_contract_args(args)

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


def _test_run_baseline_enforces_sample_count_conservation_contract():
    args = argparse.Namespace(
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    out = run_baseline(
        [
            {
                "snapshot_ts_ms": 1_000,
                "sources": [
                    {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                    {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
                ],
            },
            {
                "snapshot_ts_ms": 1_000,
                "sources": [
                    {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                ],
            },
        ],
        args,
    )
    rejected_total = (
        out["oracle_stale_reject_total"]
        + out["oracle_quorum_reject_total"]
        + out["oracle_drift_reject_total"]
    )
    assert out["accepted_total"] + rejected_total == out["sample_count"]


def _test_run_baseline_rejects_empty_fixture_list_with_stable_error():
    args = argparse.Namespace(
        min_sources=2,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    try:
        run_baseline([], args)
        raise AssertionError("empty baseline input should fail closed")
    except SystemExit as exc:
        assert str(exc) == "baseline input must contain at least one case"


def _test_run_baseline_fail_closed_on_invalid_policy_bounds_even_when_imported_directly():
    args = argparse.Namespace(
        min_sources=0,
        max_staleness_ms=60_000,
        max_deviation_bps=500,
    )
    try:
        run_baseline(
            [
                {
                    "snapshot_ts_ms": 1_000,
                    "sources": [
                        {"source": "s1", "value": 100.0, "ts_unix_ms": 1_000},
                        {"source": "s2", "value": 100.0, "ts_unix_ms": 1_000},
                    ],
                }
            ],
            args,
        )
        raise AssertionError("run_baseline should fail closed on invalid imported policy args")
    except SystemExit as exc:
        assert str(exc) == "min_sources must be > 0"


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



def _test_validate_contract_args_fail_closed_on_invalid_policy_bounds():
    class Args:
        min_sources = 0
        max_staleness_ms = 60_000
        max_deviation_bps = 500

    try:
        _validate_contract_args(Args())
        raise AssertionError("min_sources=0 should fail closed")
    except SystemExit as exc:
        assert str(exc) == "min_sources must be > 0"

    Args.min_sources = 2
    Args.max_staleness_ms = 0
    try:
        _validate_contract_args(Args())
        raise AssertionError("max_staleness_ms=0 should fail closed")
    except SystemExit as exc:
        assert str(exc) == "max_staleness_ms must be > 0"

    Args.max_staleness_ms = 60_000
    Args.max_deviation_bps = -1
    try:
        _validate_contract_args(Args())
        raise AssertionError("negative max_deviation_bps should fail closed")
    except SystemExit as exc:
        assert str(exc) == "max_deviation_bps must be between 0 and 10000"

    Args.max_deviation_bps = 10_001
    try:
        _validate_contract_args(Args())
        raise AssertionError("max_deviation_bps > 10000 should fail closed")
    except SystemExit as exc:
        assert str(exc) == "max_deviation_bps must be between 0 and 10000"



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
