#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TS="$(date +%Y%m%d-%H%M%S)"
RUN_ROOT="${RUN_ROOT:-$ROOT/run/health/gate-oneshot-$TS}"
CONS_OUT="$RUN_ROOT/consensus-security"
PHASEA_OUT_DIR="$RUN_ROOT/agent-user-phasea"
FAULT_OUT_DIR="$RUN_ROOT/phasea-fault-suite"

mkdir -p "$RUN_ROOT"

echo "[one-shot] run_root=$RUN_ROOT"
echo "[one-shot] step1: consensus security matrix"
OUT_DIR="$CONS_OUT" ./scripts/run_consensus_security_matrix.sh

# fail-fast: only reaches here if step1 exits 0
PROOF_LOG="$RUN_ROOT/proof-gate.log"
echo "[one-shot] step2: relay proof smoke + tamper matrix"
cargo test -q -p trnm-rpc relay_session_proof_smoke_and_tamper_matrix | tee "$PROOF_LOG"

echo "[one-shot] step3: agent-user phaseA gate"
OUT_DIR="$PHASEA_OUT_DIR" ./scripts/run_agent_user_phasea_gate.sh

echo "[one-shot] step4: phaseA fault injection suite"
OUT_DIR="$FAULT_OUT_DIR" ./scripts/run_phasea_fault_injection_suite.sh

echo "[one-shot][OK] all gates passed"
echo "[one-shot] consensus_summary=$CONS_OUT/summary.txt"
echo "[one-shot] proof_log=$PROOF_LOG"
echo "[one-shot] phasea_report_dir=$PHASEA_OUT_DIR"
echo "[one-shot] phasea_fault_summary=$FAULT_OUT_DIR/summary.txt"

# Emit block-level SHA256 state roots from consensus logs for quick visibility.
BASELINE_LOG="$(ls -1t "$CONS_OUT"/consensus-fault-baseline-*.log 2>/dev/null | head -n1 || true)"
if [[ -n "$BASELINE_LOG" && -f "$BASELINE_LOG" ]]; then
  HASH_OUT="$RUN_ROOT/block-state-roots.txt"
  grep '^\[block\].*state_root=' "$BASELINE_LOG" | grep -oE 'state_root=[0-9a-f]{64}' | sed 's/^state_root=//' > "$HASH_OUT" || true
  if [[ -s "$HASH_OUT" ]]; then
    echo "[one-shot] block_state_roots_file=$HASH_OUT"
    echo "[one-shot] block_state_roots_preview=$(head -n 5 "$HASH_OUT" | paste -sd, -)"
  fi
fi

echo "[one-shot] run_root=$RUN_ROOT"
