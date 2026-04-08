#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Keep parsing/output deterministic across CI runners and local replays.
export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-$LC_ALL}"

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

file_mtime() {
  local path="$1"
  # BSD/macOS: stat -f %m, GNU/Linux: stat -c %Y
  if stat -f '%m' "$path" >/dev/null 2>&1; then
    stat -f '%m' "$path"
  else
    stat -c '%Y' "$path"
  fi
}

latest_file() {
  local pattern="$1"
  local label="$2"
  local latest=""
  local latest_mtime=""

  # Use nullglob + explicit mtime comparison to avoid brittle `ls` parsing and
  # keep behavior deterministic across BSD/GNU userlands.
  shopt -s nullglob
  local matches=( $pattern )
  shopt -u nullglob

  if [[ ${#matches[@]} -eq 0 ]]; then
    echo "missing required $label artifact (pattern: $pattern)" >&2
    echo "hint: run the corresponding gate job before enforce_ci_thresholds.sh" >&2
    exit 66
  fi

  local candidate=""
  local mtime=""
  for candidate in "${matches[@]}"; do
    mtime="$(file_mtime "$candidate")"
    if [[ -z "$latest" || "$mtime" -gt "$latest_mtime" || ( "$mtime" -eq "$latest_mtime" && "$candidate" > "$latest" ) ]]; then
      latest="$candidate"
      latest_mtime="$mtime"
    fi
  done

  printf '%s\n' "$latest"
}

latest_audit="$(latest_file 'run/audit/state-root-audit-*.txt' 'audit')"
latest_bench="$(latest_file 'run/bench/bench-matrix-*.txt' 'bench')"
latest_mixed="$(latest_file 'run/bench/bench-mixed-matrix-*.txt' 'bench_mixed')"

echo "threshold.profile=$PROFILE"
echo "threshold.classic.warn_ms=$BENCH_WARN_MS"
echo "threshold.classic.hard_ms=$BENCH_MAX_MS"
echo "threshold.mixed.warn_ms=$BENCH_MIXED_WARN_MS"
echo "threshold.mixed.hard_ms=$BENCH_MIXED_MAX_MS"

echo "Using audit report: $latest_audit"
grep -q 'summary ok=true mismatch=0' "$latest_audit"

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
