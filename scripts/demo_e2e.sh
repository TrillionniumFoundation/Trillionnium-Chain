#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
KEYRING="${KEYRING:-test}"
WORKER_KEY="${WORKER_KEY:-alice}"
TASK_PATH="${TASK_PATH:-$ROOT/tasks/example_futures}"
COUNT="${COUNT:-2}"
MODE="${MODE:-full}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

tx_ok() {
  local out rc attempt=0
  while (( attempt < 6 )); do
    set +e
    out="$($@ 2>&1)"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]] && grep -q "code: 0" <<<"$out"; then
      echo "$out" | sed -n '1,40p'
      return 0
    fi

    if grep -qi "account sequence mismatch" <<<"$out"; then
      ((attempt++))
      sleep 0.8
      continue
    fi

    echo "$out"
    return 1
  done

  echo "$out"
  return 1
}

ensure_chain() {
  log "Preflight: checking chain status"
  "$BIN" status --node "$NODE" >/dev/null
}

ensure_worker_registered() {
  log "Ensuring worker is registered in workload module"
  local worker_addr
  worker_addr="$($BIN keys show "$WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"

  if $BIN query workload show-worker "$worker_addr" --node "$NODE" --home "$HOME_DIR" >/dev/null 2>&1; then
    echo "worker already registered: $worker_addr"
    return 0
  fi

  tx_ok "$BIN" tx workload register-worker "$WORKER_KEY" "ipfs://worker-$WORKER_KEY" \
    --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5
}

run_happy_path() {
  log "Running happy-path compute demo (worker executes jobs and commits results)"
  "$ROOT/scripts/e2e_smoke.sh" "$COUNT"
}

run_unbonding_guard_check() {
  log "Running unbonding guard check (request unbonding + early finalize should fail)"
  local worker_addr
  worker_addr="$($BIN keys show "$WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"

  # If an old unbonding exists, first probe finalize behavior.
  if $BIN query workload show-unbonding "$worker_addr" --node "$NODE" --home "$HOME_DIR" >/dev/null 2>&1; then
    log "Existing unbonding found; probing finalize behavior"
    set +e
    probe_out="$($BIN tx workload finalize-unbonding \
      --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
      --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
    probe_rc=$?
    set -e

    if [[ $probe_rc -eq 0 ]] && grep -q "code: 0" <<<"$probe_out"; then
      echo "$probe_out" | sed -n '1,80p'
      log "Existing unbonding finalized; creating a fresh unbonding for cooldown test"
      ensure_worker_registered
    else
      if grep -Eqi "cooldown not reached|unbonding cooldown not reached" <<<"$probe_out"; then
        echo "$probe_out" | sed -n '1,120p'
        echo "✅ Cooldown guard works: finalize-unbonding rejected during active cooldown"
        return 0
      fi
      if ! grep -qi "account sequence mismatch" <<<"$probe_out"; then
        echo "$probe_out"
        return 1
      fi
    fi
  fi

  ensure_worker_registered

  set +e
  req_out=$(tx_ok "$BIN" tx workload request-unbonding \
    --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)
  req_rc=$?
  set -e
  if [[ $req_rc -ne 0 ]]; then
    echo "$req_out"
    return 1
  fi

  log "Attempting immediate finalize-unbonding (must fail due to cooldown)"
  local attempts=0 out rc
  while (( attempts < 6 )); do
    set +e
    out="$($BIN tx workload finalize-unbonding \
      --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
      --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]] && grep -q "code: 0" <<<"$out"; then
      echo "$out"
      echo "❌ Unexpected success: finalize-unbonding passed immediately after request"
      return 1
    fi

    if grep -qi "account sequence mismatch" <<<"$out"; then
      ((attempts++))
      sleep 0.8
      continue
    fi

    if grep -Eqi "cooldown not reached|unbonding cooldown not reached" <<<"$out"; then
      echo "$out" | sed -n '1,120p'
      echo "✅ Cooldown guard works: immediate finalize-unbonding rejected"
      return 0
    fi

    echo "$out"
    return 1
  done

  echo "❌ Inconclusive: finalize-unbonding kept failing with sequence mismatch"
  return 1
}

main() {
  log "Trillionnium demo_e2e start (MODE=$MODE, COUNT=$COUNT)"
  ensure_chain
  ensure_worker_registered

  case "$MODE" in
    happy)
      run_happy_path
      ;;
    unbonding)
      run_unbonding_guard_check
      ;;
    full)
      run_happy_path
      run_unbonding_guard_check
      ;;
    *)
      echo "Unknown MODE=$MODE (use: happy|unbonding|full)"
      exit 2
      ;;
  esac

  log "Demo finished ✅"
}

main "$@"
