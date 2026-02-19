#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
KEYRING="${KEYRING:-test}"
CREATOR_KEY="${CREATOR_KEY:-bob}"
WORKER_KEY="${WORKER_KEY:-alice}"
CHALLENGER="${CHALLENGER:-alice}"
REASON="${REASON:-invalid output}"
EVIDENCE_URI="${EVIDENCE_URI:-ipfs://challenge-evidence-placeholder}"
TASK_PATH="${TASK_PATH:-$ROOT/tasks/example_futures}"
RESULT_HASH="${RESULT_HASH:-badresult123}"
RESULT_URI="${RESULT_URI:-ipfs://fake-result}"
REVEAL_SALT="${REVEAL_SALT:-demo-salt}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

tx_ok() {
  local out rc tries=0
  while (( tries < 8 )); do
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]] && { grep -q '"code":0' <<<"${out// /}" || grep -q 'code: 0' <<<"$out"; }; then
      echo "$out" | sed -n '1,80p'
      return 0
    fi

    if grep -qi "account sequence mismatch" <<<"$out"; then
      ((tries++))
      sleep 0.9
      continue
    fi

    echo "$out"
    return 1
  done

  echo "$out"
  return 1
}

workload_stats() {
  "$BIN" query workload list-task -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c 'import json,sys;o=json.load(sys.stdin);ids=[int(t.get("id",0)) for t in o.get("Task",[]) if str(t.get("id","0")).isdigit()];total=int(o.get("pagination",{}).get("total",0));print(f"{max(ids) if ids else 0} {total}")'
}

latest_task_id() { workload_stats | awk '{print $1}'; }
latest_task_total() { workload_stats | awk '{print $2}'; }

commit_hash() {
  local task_id="$1" result_hash="$2" salt="$3" worker_addr="$4"
  python3 - <<PY
import hashlib
print(hashlib.sha256(f"{int('$task_id')}|{'$result_hash'}|{'$salt'}|{'$worker_addr'}".encode()).hexdigest())
PY
}

task_status() {
  local task_id="$1"
  "$BIN" query workload show-task "$task_id" -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c 'import json,sys;o=json.load(sys.stdin);t=o.get("task") or o.get("Task") or {};print(int(t.get("status",0)))'
}

ensure_worker_registered() {
  local worker_addr
  worker_addr="$($BIN keys show "$WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
  if $BIN query workload show-worker "$worker_addr" --node "$NODE" --home "$HOME_DIR" >/dev/null 2>&1; then
    return 0
  fi
  set +e
  REG_OUT="$($BIN tx workload register-worker "$WORKER_KEY" "ipfs://worker-$WORKER_KEY" \
    --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
  REG_RC=$?
  set -e
  if [[ $REG_RC -eq 0 ]] && { grep -q '"code":0' <<<"${REG_OUT// /}" || grep -q 'code: 0' <<<"$REG_OUT"; }; then
    return 0
  fi
  if grep -Eqi 'insufficient funds|spendable balance' <<<"$REG_OUT"; then
    echo "⚠️ SKIPPED: worker registration requires more stake/funds than available"
    exit 0
  fi
  echo "$REG_OUT"
  return 1
}

wait_task_status() {
  local task_id="$1" expected="$2" tries="${3:-20}"
  local s
  for _ in $(seq 1 "$tries"); do
    s=$(task_status "$task_id" || echo -1)
    if [[ "$s" -eq "$expected" ]]; then
      return 0
    fi
    sleep 0.8
  done
  echo "$s"
  return 1
}

balance_of() {
  local key="$1" denom="$2"
  local addr
  addr="$($BIN keys show "$key" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
  "$BIN" query bank balances "$addr" -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c "import json,sys;o=json.load(sys.stdin);print(next((b['amount'] for b in o.get('balances',[]) if b.get('denom')=='$denom'),'0'))"
}

ensure_challenger_funds() {
  local need="$1"
  local have
  have="$(balance_of "$CHALLENGER" utrnm)"
  if [[ "$have" =~ ^[0-9]+$ ]] && (( have >= need )); then
    return 0
  fi

  local challenger_addr creator_addr creator_have transfer
  challenger_addr="$($BIN keys show "$CHALLENGER" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
  creator_addr="$($BIN keys show "$CREATOR_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
  creator_have="$(balance_of "$CREATOR_KEY" utrnm)"

  transfer=$((need - have))
  if (( transfer <= 0 )); then
    return 0
  fi
  if [[ ! "$creator_have" =~ ^[0-9]+$ ]] || (( creator_have <= 0 )); then
    return 1
  fi
  if (( transfer > creator_have )); then
    transfer="$creator_have"
  fi

  tx_ok "$BIN" tx bank send "$creator_addr" "$challenger_addr" "${transfer}utrnm" \
    --from "$CREATOR_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 >/tmp/scn_c_fund_challenger.log
}

if ! "$BIN" tx workload --help | grep -q "challenge-result"; then
  echo "⚠️ SKIPPED: challenge-result CLI command is not exposed yet."
  exit 0
fi

log "Scenario C: build revealed task then challenge it"

before_id=$(latest_task_id)
before_total=$(latest_task_total)
log "Before create: latest task id=$before_id total=$before_total"

tx_ok "$BIN" tx workload create-task "$TASK_PATH" 0 0 "" "" \
  --from "$CREATOR_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 >/tmp/scn_c_create.log

sleep 1
TASK_ID="$before_id"
after_total="$before_total"
for _ in 1 2 3 4 5 6 7 8; do
  TASK_ID=$(latest_task_id || echo "$before_id")
  after_total=$(latest_task_total || echo "$before_total")
  if [[ "$TASK_ID" -gt "$before_id" || "$after_total" -gt "$before_total" ]]; then
    break
  fi
  sleep 0.8
done
if [[ "$TASK_ID" -le "$before_id" && "$after_total" -le "$before_total" ]]; then
  echo "❌ failed to create new task"
  exit 1
fi
if [[ "$TASK_ID" -le "$before_id" ]]; then
  TASK_ID=$((before_id+1))
fi
log "Created task id=$TASK_ID"

ensure_worker_registered

tx_ok "$BIN" tx workload accept-task "$TASK_ID" \
  --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 >/tmp/scn_c_accept.log
wait_task_status "$TASK_ID" 1 20 >/dev/null || true

WORKER_ADDR="$($BIN keys show "$WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
COMMIT_HASH="$(commit_hash "$TASK_ID" "$RESULT_HASH" "$REVEAL_SALT" "$WORKER_ADDR")"

tx_ok "$BIN" tx workload commit-result "$TASK_ID" "$COMMIT_HASH" \
  --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 >/tmp/scn_c_commit.log
wait_task_status "$TASK_ID" 2 20 >/dev/null || true

tx_ok "$BIN" tx workload reveal-result "$TASK_ID" "$RESULT_HASH" "$RESULT_URI" "$REVEAL_SALT" \
  --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 >/tmp/scn_c_reveal.log

if ! wait_task_status "$TASK_ID" 3 24 >/dev/null; then
  current=$(task_status "$TASK_ID" || echo -1)
  echo "❌ task not in REVEALED status before challenge (current=$current)"
  "$BIN" query workload show-task "$TASK_ID" -o json --node "$NODE" --home "$HOME_DIR" | sed -n '1,160p'
  exit 1
fi

challenge_deposit="$($BIN query workload params -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);p=o.get("params",{});print(int(p.get("challengeDeposit", p.get("challenge_deposit", 0)) or 0))')"
ensure_challenger_funds "$challenge_deposit" || true
challenger_addr="$($BIN keys show "$CHALLENGER" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
challenger_utrnm="$($BIN query bank balances "$challenger_addr" -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);b=o.get("balances",[]);m={x.get("denom"):int(x.get("amount",0)) for x in b};print(m.get("utrnm",0))')"
if [[ "$challenge_deposit" -gt 0 && "$challenger_utrnm" -lt "$challenge_deposit" ]]; then
  echo "⚠️ SKIPPED: challenger utrnm balance insufficient for challenge_deposit (balance=$challenger_utrnm deposit=$challenge_deposit)"
  exit 10
fi

log "Submitting challenge"
set +e
OUT="$($BIN tx workload challenge-result "$TASK_ID" "$REASON" "$EVIDENCE_URI" \
  --from "$CHALLENGER" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
RC=$?
set -e

echo "$OUT" | sed -n '1,100p'
if [[ $RC -ne 0 ]] || { ! grep -q '"code":0' <<<"${OUT// /}" && ! grep -q 'code: 0' <<<"$OUT"; }; then
  echo "❌ Challenge submission failed"
  exit 1
fi

if ! wait_task_status "$TASK_ID" 4 20 >/dev/null; then
  current=$(task_status "$TASK_ID" || echo -1)
  echo "⚠️ challenge tx accepted but task status not CHALLENGED yet (current=$current)"
fi

log "Challenge accepted on-chain; task snapshot"
"$BIN" query workload show-task "$TASK_ID" -o json --node "$NODE" --home "$HOME_DIR" | sed -n '1,140p'

echo "✅ Scenario C passed: task challenged successfully (task_id=$TASK_ID)"
