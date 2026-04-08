#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] pouw_challenge_timeout_migration: challenge -> timeout migration"
LIST_FILE="$(mktemp -t trnm-challenge-timeout-list.XXXXXX)"
trap 'rm -f "$LIST_FILE"' EXIT

cargo test -q --workspace -- --list >"$LIST_FILE"

TESTS=()
while IFS= read -r line; do
  TESTS+=("$line")
done < <(grep -Ei '^.*(challenge.*timeout|challenged.*timeout|timeout.*challenge).*: test$' "$LIST_FILE" | sed 's/: test$//' | sort -u)

if [[ ${#TESTS[@]} -eq 0 ]]; then
  echo "[FAIL] no challenge-timeout tests found in workspace test list"
  echo "[HINT] expected test names to contain keywords: challenge + timeout"
  exit 1
fi

for t in "${TESTS[@]}"; do
  echo "[RUN] $t"
  cargo test -q --workspace "$t" -- --nocapture
done

echo "[OK] pouw_challenge_timeout_migration passed (${#TESTS[@]} tests)"
