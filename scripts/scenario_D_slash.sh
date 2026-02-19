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
TASK_ID="${TASK_ID:-}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

worker_addr="$($BIN keys show "$TARGET_WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"

if [[ -z "$TASK_ID" ]]; then
  TASK_ID="$($BIN query workload list-task -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);ids=[int(t.get("id",0)) for t in o.get("Task",[]) if str(t.get("status","0"))=="4" and str(t.get("id","0")).isdigit()];print(max(ids) if ids else 0)')"
fi

if [[ "$TASK_ID" -gt 0 ]] && "$BIN" tx workload --help | grep -q "resolve-challenge"; then
  log "Scenario D (Resolve auth): verify unauthorized resolve-challenge is blocked (task_id=$TASK_ID)"
  set +e
  RESOLVE_OUT="$($BIN tx workload resolve-challenge "$TASK_ID" true "" "unauth-resolve-test" \
    --from "$UNAUTH_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
  RESOLVE_RC=$?
  set -e
  echo "$RESOLVE_OUT" | sed -n '1,120p'
  if [[ $RESOLVE_RC -eq 0 ]] && grep -q "code: 0" <<<"$RESOLVE_OUT"; then
    echo "❌ Unauthorized resolve-challenge unexpectedly succeeded"
    exit 1
  fi
  echo "✅ Unauthorized resolve-challenge rejected as expected"
fi

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
- Positive slash path (challenge succeeded -> authority resolve/slash execution) remains pending
  until authority signing route (gov/module authority) is wired for demo.
EOF
