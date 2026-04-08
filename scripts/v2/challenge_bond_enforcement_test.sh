#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
# Keep test discovery and ordering deterministic across CI locales/timezones.
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export TZ="${TZ:-UTC}"

echo "[TEST] challenge_bond_enforcement: challenge bond guardrails"
LIST_FILE="$(mktemp -t trnm-challenge-bond-list.XXXXXX)"
trap 'rm -f "$LIST_FILE"' EXIT

cargo test -q --workspace -- --list >"$LIST_FILE"

TESTS=()
while IFS= read -r line; do
  TESTS+=("$line")
done < <(grep -Ei '^.*(challenge.*bond.*enforce|bond.*challenge.*enforce|challenge.*min.*bond|apply_challenge.*bond).*: test$' "$LIST_FILE" | sed 's/: test$//' | LC_ALL=C sort -u)

if [[ ${#TESTS[@]} -eq 0 ]]; then
  echo "[FAIL] no challenge bond enforcement tests found in workspace test list"
  echo "[HINT] expected test names to contain keywords: challenge + bond (+ enforce/min)"
  exit 1
fi

for t in "${TESTS[@]}"; do
  echo "[RUN] $t"
  cargo test -q --workspace "$t" -- --nocapture
done

echo "[OK] challenge_bond_enforcement passed (${#TESTS[@]} tests)"
