#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="${THRESHOLD_PROFILE:-stage1}"

case "$PROFILE" in
  stage1)
    CLASSIC_WARN_DEFAULT=300
    CLASSIC_HARD_DEFAULT=600
    MIXED_WARN_DEFAULT=300
    MIXED_HARD_DEFAULT=600
    ;;
  stage2)
    CLASSIC_WARN_DEFAULT=240
    CLASSIC_HARD_DEFAULT=480
    MIXED_WARN_DEFAULT=280
    MIXED_HARD_DEFAULT=560
    ;;
  *)
    echo "unknown THRESHOLD_PROFILE=$PROFILE (expected: stage1|stage2)" >&2
    exit 11
    ;;
esac

BENCH_WARN_MS="${BENCH_WARN_MS:-$CLASSIC_WARN_DEFAULT}"
BENCH_MAX_MS="${BENCH_MAX_MS:-$CLASSIC_HARD_DEFAULT}"
BENCH_MIXED_WARN_MS="${BENCH_MIXED_WARN_MS:-$MIXED_WARN_DEFAULT}"
BENCH_MIXED_MAX_MS="${BENCH_MIXED_MAX_MS:-$MIXED_HARD_DEFAULT}"

latest_audit="$(ls -1dt run/audit/state-root-audit-*.txt | head -n 1)"
latest_bench="$(ls -1dt run/bench/bench-matrix-*.txt | head -n 1)"
latest_mixed="$(ls -1dt run/bench/bench-mixed-matrix-*.txt | head -n 1)"

echo "threshold.profile=$PROFILE"
echo "threshold.classic.warn_ms=$BENCH_WARN_MS"
echo "threshold.classic.hard_ms=$BENCH_MAX_MS"
echo "threshold.mixed.warn_ms=$BENCH_MIXED_WARN_MS"
echo "threshold.mixed.hard_ms=$BENCH_MIXED_MAX_MS"

echo "Using audit report: $latest_audit"
grep -q 'summary ok=true mismatch=0 missing=0' "$latest_audit"

echo "Using bench report: $latest_bench"
echo "Using mixed bench report: $latest_mixed"

check_elapsed_file() {
  local file="$1"
  local label="$2"
  local warn="$3"
  local hard="$4"
  awk -F= -v warn="$warn" -v hard="$hard" -v label="$label" '
    /^elapsed_ms=/ {
      v=$2+0
      if (v > warn) {
        printf("::warning::%s elapsed above warn threshold: %dms (warn=%d, hard=%d)\n", label, v, warn, hard)
      }
      if (v > hard) {
        printf("%s elapsed above hard threshold: %dms (hard=%d)\n", label, v, hard)
        bad=1
      }
    }
    END{ exit bad }
  ' "$file"
}

check_elapsed_file "$latest_bench" "bench" "$BENCH_WARN_MS" "$BENCH_MAX_MS"
check_elapsed_file "$latest_mixed" "bench_mixed" "$BENCH_MIXED_WARN_MS" "$BENCH_MIXED_MAX_MS"

echo "threshold enforcement: PASS"
