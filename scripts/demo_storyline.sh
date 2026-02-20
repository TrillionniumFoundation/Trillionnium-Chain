#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/demo/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"

echo "[DEMO] start $(date '+%F %T')" | tee "$SUMMARY"

if [[ -x "$ROOT/scripts/p0_acceptance.sh" ]]; then
  if "$ROOT/scripts/p0_acceptance.sh" --quick >>"$SUMMARY" 2>&1; then
    echo "[DEMO][OK] p0 quick acceptance" | tee -a "$SUMMARY"
  else
    echo "[DEMO][WARN] p0 quick acceptance failed" | tee -a "$SUMMARY"
  fi
else
  echo "[DEMO][SKIP] p0_acceptance.sh not found" | tee -a "$SUMMARY"
fi

if "$ROOT/scripts/challenge_reexec_template_smoke.sh" >>"$SUMMARY" 2>&1; then
  echo "[DEMO][OK] challenge reexec template smoke" | tee -a "$SUMMARY"
else
  echo "[DEMO][FAIL] challenge reexec template smoke" | tee -a "$SUMMARY"
  exit 1
fi

if "$ROOT/scripts/worker_onchain_contract_smoke.sh" >>"$SUMMARY" 2>&1; then
  echo "[DEMO][OK] worker onchain contract smoke" | tee -a "$SUMMARY"
else
  echo "[DEMO][FAIL] worker onchain contract smoke" | tee -a "$SUMMARY"
  exit 1
fi

echo "[DEMO] done $(date '+%F %T')" | tee -a "$SUMMARY"
echo "$SUMMARY"
