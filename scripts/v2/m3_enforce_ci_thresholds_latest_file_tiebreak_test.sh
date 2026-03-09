#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TR="$ROOT/trillionnium-rust"
TMP="$TR/run/m3-threshold-tiebreak-test"
OUT="$TMP/out.log"

cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/audit" "$TMP/bench"

AUDIT_OLD="$TMP/audit/state-root-audit-20260310-aaa.txt"
AUDIT_NEW="$TMP/audit/state-root-audit-20260310-bbb.txt"
BENCH_OLD="$TMP/bench/bench-matrix-20260310-aaa.txt"
BENCH_NEW="$TMP/bench/bench-matrix-20260310-bbb.txt"
MIXED_OLD="$TMP/bench/bench-mixed-matrix-20260310-aaa.txt"
MIXED_NEW="$TMP/bench/bench-mixed-matrix-20260310-bbb.txt"

printf 'summary ok=true mismatch=0\n' > "$AUDIT_OLD"
printf 'summary ok=true mismatch=0\n' > "$AUDIT_NEW"
printf 'elapsed_ms=1\n' > "$BENCH_OLD"
printf 'elapsed_ms=1\n' > "$BENCH_NEW"
printf 'elapsed_ms=1\n' > "$MIXED_OLD"
printf 'elapsed_ms=1\n' > "$MIXED_NEW"

# Force identical mtimes; deterministic tie-break should choose lexicographically later path.
touch -t 202603100101 "$AUDIT_OLD" "$AUDIT_NEW" "$BENCH_OLD" "$BENCH_NEW" "$MIXED_OLD" "$MIXED_NEW"

(
  cd "$TR"
  RUN_DIR_OVERRIDE="$TMP" \
  bash -c '
    mkdir -p run/audit run/bench
    cp "$RUN_DIR_OVERRIDE"/audit/* run/audit/
    cp "$RUN_DIR_OVERRIDE"/bench/* run/bench/
    ./scripts/enforce_ci_thresholds.sh
  '
) > "$OUT"

if ! grep -Fq "Using audit report: run/audit/state-root-audit-20260310-bbb.txt" "$OUT"; then
  echo "[FAIL] audit tie-break did not pick lexicographically latest file" >&2
  cat "$OUT" >&2
  exit 1
fi

if ! grep -Fq "Using bench report: run/bench/bench-matrix-20260310-bbb.txt" "$OUT"; then
  echo "[FAIL] bench tie-break did not pick lexicographically latest file" >&2
  cat "$OUT" >&2
  exit 1
fi

if ! grep -Fq "Using mixed bench report: run/bench/bench-mixed-matrix-20260310-bbb.txt" "$OUT"; then
  echo "[FAIL] mixed bench tie-break did not pick lexicographically latest file" >&2
  cat "$OUT" >&2
  exit 1
fi

echo "[PASS] enforce_ci_thresholds deterministic latest-file tie-break is stable"