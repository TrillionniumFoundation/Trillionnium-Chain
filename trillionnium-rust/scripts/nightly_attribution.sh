#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="${THRESHOLD_PROFILE:-stage2}"
case "$PROFILE" in
  stage1)
    CLASSIC_HARD_DEFAULT=600
    MIXED_HARD_DEFAULT=600
    ;;
  stage2)
    CLASSIC_HARD_DEFAULT=480
    MIXED_HARD_DEFAULT=560
    ;;
  *)
    CLASSIC_HARD_DEFAULT=480
    MIXED_HARD_DEFAULT=560
    ;;
esac

CLASSIC_HARD_MS="${BENCH_MAX_MS:-$CLASSIC_HARD_DEFAULT}"
MIXED_HARD_MS="${BENCH_MIXED_MAX_MS:-$MIXED_HARD_DEFAULT}"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="run/health"
OUT="$OUT_DIR/nightly-attribution-$TS.txt"
mkdir -p "$OUT_DIR"

latest_audit="$(ls -1dt run/audit/state-root-audit-*.txt 2>/dev/null | head -n 1 || true)"
latest_bench="$(ls -1dt run/bench/bench-matrix-*.txt 2>/dev/null | head -n 1 || true)"
latest_mixed="$(ls -1dt run/bench/bench-mixed-matrix-*.txt 2>/dev/null | head -n 1 || true)"

label_semantic=0
label_perf=0
label_env=0

reasons=()

if [[ -z "$latest_audit" ]] || [[ -z "$latest_bench" ]] || [[ -z "$latest_mixed" ]]; then
  label_env=1
  reasons+=("missing_expected_artifacts")
fi

if [[ -n "$latest_audit" ]]; then
  if ! grep -q 'summary ok=true mismatch=0 missing=0' "$latest_audit"; then
    label_semantic=1
    reasons+=("state_root_audit_failed")
  fi
fi

if [[ -f run/parallel-sanity.log ]]; then
  if grep -E '\[tx\] apply_error|rollback=true' run/parallel-sanity.log >/dev/null; then
    label_semantic=1
    reasons+=("parallel_apply_error_or_rollback")
  fi
fi

if [[ -f run/event-replay-smoke.log ]]; then
  if ! grep -q 'event_type=resolve' run/event-replay-smoke.log; then
    label_semantic=1
    reasons+=("event_replay_order_failed")
  fi
fi

max_elapsed() {
  local file="$1"
  awk -F= '/^elapsed_ms=/{if ($2+0>m) m=$2+0} END{if (m=="") m=0; print m}' "$file"
}

if [[ -n "$latest_bench" ]]; then
  classic_max="$(max_elapsed "$latest_bench")"
  if [[ "$classic_max" -gt "$CLASSIC_HARD_MS" ]]; then
    label_perf=1
    reasons+=("classic_elapsed_gt_hard(${classic_max}>${CLASSIC_HARD_MS})")
  fi
fi

if [[ -n "$latest_mixed" ]]; then
  mixed_max="$(max_elapsed "$latest_mixed")"
  if [[ "$mixed_max" -gt "$MIXED_HARD_MS" ]]; then
    label_perf=1
    reasons+=("mixed_elapsed_gt_hard(${mixed_max}>${MIXED_HARD_MS})")
  fi
fi

labels=()
[[ $label_semantic -eq 1 ]] && labels+=("semantic-regression")
[[ $label_perf -eq 1 ]] && labels+=("performance-regression")
[[ $label_env -eq 1 ]] && labels+=("environment-flaky")
if [[ ${#labels[@]} -eq 0 ]]; then
  labels+=("healthy")
fi

{
  echo "attribution.profile=$PROFILE"
  echo "attribution.labels=$(IFS=,; echo "${labels[*]}")"
  echo "attribution.reasons=$(IFS=';'; echo "${reasons[*]:-none}")"
  echo "audit.file=${latest_audit:-none}"
  echo "bench.file=${latest_bench:-none}"
  echo "mixed.file=${latest_mixed:-none}"
  echo "threshold.classic.hard_ms=$CLASSIC_HARD_MS"
  echo "threshold.mixed.hard_ms=$MIXED_HARD_MS"
} | tee "$OUT"

echo "::notice title=nightly-attribution::labels=$(IFS=,; echo "${labels[*]}")"
echo "[OK] nightly attribution: $OUT"
