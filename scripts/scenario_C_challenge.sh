#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

log "Scenario C (Invalid Result Challenge) skeleton"
if ! "$BIN" tx workload --help | grep -q "challenge-result"; then
  cat <<'EOF'
⚠️  SKIPPED: challenge-result CLI command is not exposed yet.

Next enablement steps:
1) expose MsgChallengeResult / MsgResolveChallenge in workload autocli config;
2) regenerate cli commands;
3) rerun this scenario with:
   TASK_ID=<id> CHALLENGER=<key> ./scripts/scenario_C_challenge.sh
EOF
  exit 0
fi

TASK_ID="${TASK_ID:-}"
CHALLENGER="${CHALLENGER:-bob}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
REASON="${REASON:-invalid output}"
EVIDENCE_URI="${EVIDENCE_URI:-ipfs://challenge-evidence-placeholder}"

if [[ -z "$TASK_ID" ]]; then
  echo "Usage: TASK_ID=<id> [CHALLENGER=bob] ./scripts/scenario_C_challenge.sh"
  exit 2
fi

set +e
OUT="$($BIN tx workload challenge-result "$TASK_ID" "$REASON" "$EVIDENCE_URI" \
  --from "$CHALLENGER" --keyring-backend test --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
RC=$?
set -e

echo "$OUT" | sed -n '1,120p'
if [[ $RC -eq 0 ]] && grep -q "code: 0" <<<"$OUT"; then
  echo "✅ Challenge submitted (follow up with resolve-challenge in scenario D/manual flow)"
  exit 0
fi

if grep -qi "unable to resolve type URL" <<<"$OUT"; then
  cat <<'EOF'
⚠️  CLI command is present, but running node binary doesn't recognize MsgChallengeResult yet.
Likely node is still on an older build.

Action:
1) restart local chain with latest ./build/chaind
2) retry: TASK_ID=<id> CHALLENGER=<key> ./scripts/scenario_C_challenge.sh
EOF
  exit 1
fi

echo "❌ Challenge submission failed"
exit 1
