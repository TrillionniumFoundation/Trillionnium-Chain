#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

OUT_DIR="run/challenges"
OUT="$OUT_DIR/bft-message-auth-gate-strength-probe-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

# 该脚本不改现有 gate；只生成对抗样本并报告“token-only检查”风险。
fake_log="$OUT_DIR/fake-bft-auth.log"
cat > "$fake_log" <<'EOF'
[bft] height=1 round=0 step=Commit block_hash=abc precommit=4/4 unique_voters=4 byzantine_votes=0 double_vote_events=0 auth_reject_bad_sig=0 auth_reject_replay=0 auth_reject_stale=0
[consensus] finality_p50_ms=1 finality_p95_ms=1 bft_committed_heights=1 bft_round_change_total=0 bft_round_change_backoff_total_ms=0 bft_double_vote_total=0 bft_auth_reject_bad_sig_total=0 bft_auth_reject_replay_total=0 bft_auth_reject_stale_nonce_total=0
EOF

# 简单“存在性”检查（模拟当前 gate 风格）
has_commit=$(grep -c '^\[bft\].*step=Commit' "$fake_log" || true)
has_consensus=$(grep -c '^\[consensus\].*bft_auth_reject_bad_sig_total=' "$fake_log" || true)
bad_sig=$(sed -n 's/.*bft_auth_reject_bad_sig_total=\([0-9]*\).*/\1/p' "$fake_log" | head -n1)
replay=$(sed -n 's/.*bft_auth_reject_replay_total=\([0-9]*\).*/\1/p' "$fake_log" | head -n1)

{
  echo "challenge=bft_message_auth_gate_strength_probe"
  echo "fake_log=$fake_log"
  echo "token_commit=$has_commit"
  echo "token_consensus_metric=$has_consensus"
  echo "bad_sig_total=${bad_sig:-n/a}"
  echo "replay_total=${replay:-n/a}"
  if [[ "$has_commit" -gt 0 && "$has_consensus" -gt 0 && "${bad_sig:-0}" -eq 0 && "${replay:-0}" -eq 0 ]]; then
    echo "result=TOKEN_CHECK_CAN_MISS_SEMANTIC_REGRESSION"
  else
    echo "result=NOT_CONFIRMED"
  fi
  echo "suggestion=add explicit numeric assertions (e.g., expected non-zero in injected-fault path or bounded ranges in normal path)"
} | tee "$OUT"

echo "[OK] report: $OUT"
