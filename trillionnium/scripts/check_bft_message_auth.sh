#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TZ="${TZ:-UTC}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export CARGO_INCREMENTAL="0"
export CARGO_TERM_COLOR="never"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

OUT_DIR="$ROOT/run"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/bft-message-auth-${TS}.log"
REPORT="$OUT_DIR/bft-message-auth-${TS}.txt"

cargo test -p trnm-consensus-crypto --locked --offline 2>&1 | tee "$LOG"

{
  echo "consensus=native-poco-bft"
  echo "test_surface=trnm-consensus-crypto"
  echo "legacy_harness=false"
  echo "log=$LOG"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] native PoCO authentication/anti-replay crypto surface passed: $REPORT"
