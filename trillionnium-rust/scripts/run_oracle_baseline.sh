#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

python3 - <<'PY'
import importlib.util
from pathlib import Path

module_path = Path("scripts/oracle/benchmark_oracle_metrics.py")
spec = importlib.util.spec_from_file_location("benchmark_oracle_metrics", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

for name in sorted(dir(module)):
    if name.startswith("_test_"):
        getattr(module, name)()
PY

BASE_OUT="$(python3 scripts/oracle/benchmark_oracle_metrics.py \
  --input scripts/oracle/fixtures/oracle_baseline_cases.json)"
BENCH_OUT="$(python3 scripts/oracle/benchmark_oracle_metrics.py \
  --bench --bench-count 1000 --bench-rounds 10)"

python3 - <<'PY' "${BASE_OUT}" "${BENCH_OUT}"
import json
import sys

baseline = json.loads(sys.argv[1])
bench = json.loads(sys.argv[2])

required_baseline = {
    "oracle_ingest_latency_ms",
    "oracle_stale_reject_total",
    "oracle_quorum_reject_total",
    "oracle_drift_reject_total",
    "oracle_source_cardinality",
    "accepted_total",
    "sample_count",
}
missing_baseline = sorted(required_baseline - baseline.keys())
if missing_baseline:
    raise SystemExit(f"baseline contract missing keys: {missing_baseline}")

extra_baseline = sorted(set(baseline.keys()) - required_baseline)
if extra_baseline:
    raise SystemExit(f"baseline contract has unexpected keys: {extra_baseline}")

rejected_total = (
    baseline["oracle_stale_reject_total"]
    + baseline["oracle_quorum_reject_total"]
    + baseline["oracle_drift_reject_total"]
)
if baseline["accepted_total"] + rejected_total != baseline["sample_count"]:
    raise SystemExit(
        "baseline contract violated: accepted_total + rejected_total must equal sample_count"
    )

if baseline["accepted_total"] == 0 and baseline["oracle_source_cardinality"] != 0:
    raise SystemExit(
        "baseline contract violated: oracle_source_cardinality must be 0 when accepted_total is 0"
    )

if baseline["accepted_total"] > 0 and baseline["oracle_source_cardinality"] == 0:
    raise SystemExit(
        "baseline contract violated: oracle_source_cardinality must be positive when accepted_total is non-zero"
    )

required_bench = {
    "bench_rounds",
    "bench_count",
    "ingest_latency_p50_ms",
    "ingest_latency_p95_ms",
    "ingest_latency_max_ms",
}
missing_bench = sorted(required_bench - bench.keys())
if missing_bench:
    raise SystemExit(f"bench contract missing keys: {missing_bench}")

extra_bench = sorted(set(bench.keys()) - required_bench)
if extra_bench:
    raise SystemExit(f"bench contract has unexpected keys: {extra_bench}")

if not (bench["ingest_latency_p50_ms"] <= bench["ingest_latency_p95_ms"] <= bench["ingest_latency_max_ms"]):
    raise SystemExit(
        "bench contract violated: latency ordering must satisfy p50 <= p95 <= max"
    )
PY

echo "[oracle-baseline] baseline"
echo "${BASE_OUT}"
echo "[oracle-baseline] bench"
echo "${BENCH_OUT}"
