#!/usr/bin/env bash
set -euo pipefail
expected='https://github.com/TrillionniumFoundation/Trillionnium-Chain'
actual="$(git remote get-url origin)"
if [[ "$actual" != "$expected" ]]; then
  printf 'checkout origin mismatch: exact canonical GitHub source required\n' >&2
  exit 2
fi
git remote set-url origin "${expected}.git"
test "$(git remote get-url origin)" = "${expected}.git"
