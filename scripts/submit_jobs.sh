#!/usr/bin/env bash
set -euo pipefail

BIN="/Users/qianqi/.openclaw/workspace/TrillionniumChain/build/chaind"
CHAIN_ID="trillionnium"
FROM_KEY="bob"
TASK_PATH="${1:-/Users/qianqi/.openclaw/workspace/TrillionniumChain/tasks/example_futures}"
REQS="${2:-cpu}"
COUNT="${3:-1}"

submit_one() {
  local attempt=0
  while (( attempt < 8 )); do
    set +e
    OUT="$($BIN tx compute create-compute-job "$TASK_PATH" "$REQS" \
      --from "$FROM_KEY" --keyring-backend test --chain-id "$CHAIN_ID" \
      --yes --gas auto --gas-adjustment 1.5 --broadcast-mode sync 2>&1)"
    RC=$?
    set -e

    if [[ $RC -eq 0 ]] && grep -q "code: 0" <<<"$OUT"; then
      echo "$OUT" | sed -n '1,20p'
      return 0
    fi

    if grep -q "account sequence mismatch" <<<"$OUT"; then
      sleep "$(python3 - <<'PY'
import random
print(0.6 + random.random()*0.7)
PY
)"
      ((attempt++))
      continue
    fi

    echo "$OUT"
    return 1
  done

  echo "submit failed after retries"
  return 1
}

for ((i=1; i<=COUNT; i++)); do
  echo "=== submit job $i/$COUNT ==="
  submit_one
  sleep 0.6
done
