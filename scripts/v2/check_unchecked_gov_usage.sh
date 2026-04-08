#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Enforce that set_gov_param_bootstrap_unchecked is only used in tests or explicitly allowed bootstrap helper.
# Allowed patterns:
# - *_test files / #[cfg(test)] blocks in source (best-effort via path filter)
# - trnm-state crate internal tests in lib.rs
# - this check script itself / docs / workflow files

hits=$(grep -RIn "set_gov_param_bootstrap_unchecked" trillionnium/crates \
  --exclude-dir target \
  --exclude-dir .git || true)

if [[ -z "${hits}" ]]; then
  echo "[OK] no set_gov_param_bootstrap_unchecked usage found"
  exit 0
fi

violations=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  path="${line%%:*}"

  case "$path" in
    */tests/*) continue ;;
    */crates/trnm-state/src/lib.rs)
      # state crate keeps test-embedded baseline coverage
      continue
      ;;
    */crates/trnm-pouw/src/lib.rs)
      # pouw currently keeps heavy governance-path coverage inside lib.rs tests
      continue
      ;;
    */crates/trnm-node/src/main.rs)
      # node has unit-test module in main.rs
      continue
      ;;
    *) ;;
  esac

  violations+=("$line")
done <<< "$hits"

if (( ${#violations[@]} > 0 )); then
  echo "[FAIL] disallowed set_gov_param_bootstrap_unchecked usage detected:" >&2
  printf '%s
' "${violations[@]}" >&2
  exit 2
fi

echo "[OK] set_gov_param_bootstrap_unchecked usage limited to allowed test/bootstrap paths"
