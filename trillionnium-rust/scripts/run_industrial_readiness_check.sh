#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-C}"

OWNER="${1:-ProfAlexQI}"
REPO="${2:-TrillionniumChain}"
REQUIRED_STREAK="${3:-3}"
case "$REQUIRED_STREAK" in
  ''|*[!0-9]*)
    echo "REQUIRED_STREAK must be a positive integer, got '$REQUIRED_STREAK'" >&2
    exit 64
    ;;
esac
if [ "$REQUIRED_STREAK" -lt 1 ]; then
  echo "REQUIRED_STREAK must be >= 1, got '$REQUIRED_STREAK'" >&2
  exit 64
fi

OUT_DIR="$ROOT/run/health"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%d-%H%M%S)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE="$OUT_DIR/industrial-readiness-${TS}.txt"
REPLAY_COMMAND="env TZ='${TZ}' LC_ALL='${LC_ALL}' LANG='${LANG}' ./scripts/run_industrial_readiness_check.sh $(printf '%q' "$OWNER") $(printf '%q' "$REPO") $(printf '%q' "$REQUIRED_STREAK")"
ROLLBACK_COMMAND="rm -f $(printf '%q' "$OUT_FILE")"

{
  echo "industrial_readiness.ts=$TS"
  echo "industrial_readiness.generated_at=$GENERATED_AT"
  echo "industrial_readiness.owner=$OWNER"
  echo "industrial_readiness.repo=$REPO"
  echo "industrial_readiness.required_streak=$REQUIRED_STREAK"
  echo "industrial_readiness.replay_command=$REPLAY_COMMAND"
  echo "industrial_readiness.rollback_command=$ROLLBACK_COMMAND"
  ./scripts/check_nightly_green_streak.sh "$OWNER" "$REPO" "$REQUIRED_STREAK"
  echo "industrial_readiness.result=PASS"
} | tee "$OUT_FILE"

echo "[OK] industrial readiness report: $OUT_FILE"
