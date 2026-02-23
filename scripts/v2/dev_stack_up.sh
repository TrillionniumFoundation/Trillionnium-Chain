#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

./scripts/v2/rpc_service_up.sh
./scripts/v2/faucet_service_up.sh
./scripts/v2/explorer_service_up.sh

for i in {1..90}; do
  RPC_OK=0; FAUCET_OK=0; EXPLORER_OK=0
  curl -fsS http://127.0.0.1:8545/health >/dev/null 2>&1 && RPC_OK=1
  curl -fsS http://127.0.0.1:8546/health >/dev/null 2>&1 && FAUCET_OK=1
  curl -fsS http://127.0.0.1:8090/ >/dev/null 2>&1 && EXPLORER_OK=1
  if [[ $RPC_OK -eq 1 && $FAUCET_OK -eq 1 && $EXPLORER_OK -eq 1 ]]; then
    echo "dev_stack.up=ok"
    echo "rpc=http://127.0.0.1:8545/health"
    echo "faucet=http://127.0.0.1:8546/health"
    echo "explorer=http://127.0.0.1:8090"
    exit 0
  fi
  sleep 1
done

echo "dev_stack.up=fail"
exit 1
