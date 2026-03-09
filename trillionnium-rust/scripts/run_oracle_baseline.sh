#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BASE_OUT="$(python3 scripts/oracle/benchmark_oracle_metrics.py \
  --input scripts/oracle/fixtures/oracle_baseline_cases.json)"
BENCH_OUT="$(python3 scripts/oracle/benchmark_oracle_metrics.py \
  --bench --bench-count 1000 --bench-rounds 10)"

echo "[oracle-baseline] baseline"
echo "${BASE_OUT}"
echo "[oracle-baseline] bench"
echo "${BENCH_OUT}"
