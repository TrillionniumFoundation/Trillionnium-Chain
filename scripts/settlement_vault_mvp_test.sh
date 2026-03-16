#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VAULT_DIR="$ROOT_DIR/contracts/settlement-vault"

if ! command -v forge >/dev/null 2>&1; then
  echo "[blocker] forge not found. Install Foundry first:"
  echo "  curl -L https://foundry.paradigm.xyz | bash"
  echo "  foundryup"
  exit 2
fi

cd "$VAULT_DIR"
forge test -vv
