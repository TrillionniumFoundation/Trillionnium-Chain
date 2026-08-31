#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run}"
TIMEOUT_SECONDS="${DEVNET_READY_TIMEOUT_SECONDS:-90}"
POLL_SECONDS="${DEVNET_READY_POLL_SECONDS:-1}"

if [[ ! "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "DEVNET_READY_TIMEOUT_SECONDS must be a non-negative integer" >&2
  exit 2
fi
if [[ ! "$POLL_SECONDS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "DEVNET_READY_POLL_SECONDS must be a non-negative number" >&2
  exit 2
fi

deadline=$((SECONDS + TIMEOUT_SECONDS))
while true; do
  ready=0
  for node in 1 2 3; do
    log="$RUN_DIR/node${node}.log"
    if [[ -f "$log" ]] && grep -qE '\[block\].*height=[0-9]+.*state_root=[0-9a-fA-F]+' "$log"; then
      ready=$((ready + 1))
      continue
    fi

    pid_file="$RUN_DIR/node${node}.pid"
    if [[ -f "$pid_file" ]]; then
      pid="$(<"$pid_file")"
      if [[ "$pid" =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null; then
        echo "devnet node${node} exited before producing a block" >&2
        [[ -f "$log" ]] && tail -n 80 "$log" >&2
        exit 1
      fi
    fi
  done

  if [[ "$ready" -eq 3 ]]; then
    echo "devnet ready: observed at least one canonical block on all 3 nodes"
    exit 0
  fi
  if (( SECONDS >= deadline )); then
    echo "devnet readiness timed out after ${TIMEOUT_SECONDS}s: ready=${ready}/3" >&2
    for node in 1 2 3; do
      log="$RUN_DIR/node${node}.log"
      if [[ -f "$log" ]]; then
        echo "--- node${node}.log (tail) ---" >&2
        tail -n 80 "$log" >&2
      else
        echo "missing log: $log" >&2
      fi
    done
    exit 1
  fi
  sleep "$POLL_SECONDS"
done
