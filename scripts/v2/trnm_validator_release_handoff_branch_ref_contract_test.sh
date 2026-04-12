#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/trillionnium/docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing validator release handoff doc: $TARGET" >&2
  exit 1
fi

required_lines=(
  'EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"'
  'If you only have the short branch name from the ticket, pass it with `--expected-branch` instead of sending it to `--expected-branch-ref`'
  'the branch-ref flag is reserved for full `refs/heads/...` values'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing branch-ref contract line: $line" >&2
    exit 1
  fi
done

echo "[PASS] validator release handoff doc keeps --expected-branch-ref pinned to full refs/heads/... values"
