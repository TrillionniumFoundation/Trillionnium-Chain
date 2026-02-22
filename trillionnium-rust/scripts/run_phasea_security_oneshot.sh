#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TS="$(date +%Y%m%d-%H%M%S)"
RUN_ROOT="${RUN_ROOT:-$ROOT/run/health/gate-oneshot-$TS}"
CONS_OUT="$RUN_ROOT/consensus-security"
PHASEA_OUT_DIR="$RUN_ROOT/agent-user-phasea"

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

echo "[one-shot][OK] all gates passed"
echo "[one-shot] consensus_summary=$CONS_OUT/summary.txt"
echo "[one-shot] proof_log=$PROOF_LOG"
echo "[one-shot] phasea_report_dir=$PHASEA_OUT_DIR"
echo "[one-shot] run_root=$RUN_ROOT"
