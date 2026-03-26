#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/docs/release/TRNM_STAGE1_DEVNET_READY_CHECKLIST_2026-03-24.md"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing checklist: $TARGET" >&2
  exit 1
fi

required_lines=(
  'branch_ref='
  'head_sha='
  '--expected-branch-ref "refs/heads/$EXPECTED_BRANCH"'
  '--expected-branch-ref "$EXPECTED_BRANCH_REF"'
  'CURRENT_BRANCH="$(git branch --show-current)"'
  'CURRENT_HEAD="$(git rev-parse HEAD)"'
  'test -n "$CURRENT_BRANCH"'
  'printf '\''branch_ref=%s\n'\'' "refs/heads/$CURRENT_BRANCH"'
  'printf '\''head_sha=%s\n'\'' "$CURRENT_HEAD"'
  '`branch` / `branch_ref` / `head_sha` 与 `commit_short` 共同固定这次证据绑定的是哪一条 lane 引用与哪一个精确提交'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing branch-binding guard line: $line" >&2
    exit 1
  fi
done

echo "[PASS] stage1 devnet checklist pins branch short name + full branch ref + exact HEAD for operator handoff evidence"
