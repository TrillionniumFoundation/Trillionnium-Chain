#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HELPER="$ROOT/scripts/v2/auto_iterate_task_add_quickcheck_step.sh"
WORKFLOW="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

before="$(sha256sum "$WORKFLOW" | awk '{print $1}')"

set +e
output="$(
  env -u TRNM_ALLOW_LEGACY_QUICKCHECK_MUTATION "$HELPER" \
    "unsafe legacy injector regression" \
    "./scripts/v2/auto_iterate_task_add_quickcheck_step_fail_closed_test.sh" \
    "test: must not commit" 2>&1
)"
rc=$?
set -e

after="$(sha256sum "$WORKFLOW" | awk '{print $1}')"

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] legacy quick-check injector must fail closed with rc=2, got rc=$rc" >&2
  echo "$output" >&2
  exit 1
fi

if [[ "$before" != "$after" ]]; then
  echo "[FAIL] legacy quick-check injector modified the workflow without explicit opt-in" >&2
  exit 1
fi

if ! grep -Fq "legacy quick-check mutation is disabled" <<<"$output"; then
  echo "[FAIL] missing fail-closed legacy injector diagnostic" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] legacy quick-check injector is fail-closed and leaves the workflow unchanged"
