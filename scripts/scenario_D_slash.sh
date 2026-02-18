#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
KEYRING="${KEYRING:-test}"
TARGET_WORKER_KEY="${TARGET_WORKER_KEY:-alice}"
UNAUTH_KEY="${UNAUTH_KEY:-bob}"
SLASH_PERCENT="${SLASH_PERCENT:-10}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

worker_addr="$($BIN keys show "$TARGET_WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"

log "Scenario D (Slash): verify unauthorized slash is blocked"
set +e
OUT="$($BIN tx workload slash-worker "$worker_addr" "$SLASH_PERCENT" \
  --from "$UNAUTH_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
RC=$?
set -e

echo "$OUT" | sed -n '1,120p'
if [[ $RC -eq 0 ]] && grep -q "code: 0" <<<"$OUT"; then
  echo "❌ Unauthorized slash unexpectedly succeeded"
  exit 1
fi

if grep -Eqi "authority|unauthorized|not authorized|unknown request" <<<"$OUT"; then
  echo "✅ Unauthorized slash rejected as expected"
else
  echo "⚠️ Slash failed (as expected) but reason did not match typical auth errors"
fi

cat <<'EOF'

Note:
- Positive slash path (challenge succeeded -> authority slash execution) remains pending
  until challenge/resolve CLI commands are exposed and governance/authority route is wired for demo.
EOF
