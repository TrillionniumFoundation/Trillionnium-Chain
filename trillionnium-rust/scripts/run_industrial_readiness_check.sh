#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OWNER="${1:-ProfAlexQI}"
REPO="${2:-TrillionniumChain}"
REQUIRED_STREAK="${3:-3}"

OUT_DIR="$ROOT/run/health"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_FILE="$OUT_DIR/industrial-readiness-${TS}.txt"

{
  echo "industrial_readiness.ts=$TS"
  echo "industrial_readiness.owner=$OWNER"
  echo "industrial_readiness.repo=$REPO"
  echo "industrial_readiness.required_streak=$REQUIRED_STREAK"
  ./scripts/check_nightly_green_streak.sh "$OWNER" "$REPO" "$REQUIRED_STREAK"
  echo "industrial_readiness.result=PASS"
} | tee "$OUT_FILE"

echo "[OK] industrial readiness report: $OUT_FILE"
