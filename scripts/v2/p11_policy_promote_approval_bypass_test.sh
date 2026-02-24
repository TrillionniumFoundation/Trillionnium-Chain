#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

POLICY="$TMP_DIR/current.json"
cp "$ROOT/config/alert-policy/current.json" "$POLICY"
PROFILE_STAGING="$ROOT/config/alert-policy/profiles/staging.json"
PROFILE_PROD="$ROOT/config/alert-policy/profiles/prod.json"
PROMO_LOG="$ROOT/run/pr11/policy-promotions.log"

hash_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    echo "MISSING"
  fi
}

before_staging_hash="$(hash_file "$PROFILE_STAGING")"
before_prod_hash="$(hash_file "$PROFILE_PROD")"
before_log_hash="$(hash_file "$PROMO_LOG")"

set +e
"$ROOT/scripts/v2/p11_policy_promote.sh" --from staging --to prod --policy "$POLICY" >"$TMP_DIR/direct.out" 2>&1
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[TEST][FAIL] direct promote without --approve should be blocked"
  cat "$TMP_DIR/direct.out"
  exit 1
fi
if [[ "$rc" -ne 3 ]]; then
  echo "[TEST][FAIL] expected rc=3 for approval block, got rc=$rc"
  cat "$TMP_DIR/direct.out"
  exit 1
fi
if ! grep -q "\[P11\]\[BLOCKED\]" "$TMP_DIR/direct.out"; then
  echo "[TEST][FAIL] missing BLOCKED marker for direct promote"
  cat "$TMP_DIR/direct.out"
  exit 1
fi

"$ROOT/scripts/v2/p11_policy_promote_gate.sh" --from staging --to prod --dry-run --policy "$POLICY" >"$TMP_DIR/gate.out" 2>&1
if ! grep -q "\[P11\]\[DRY-RUN\]" "$TMP_DIR/gate.out"; then
  echo "[TEST][FAIL] gate dry-run did not reach promote flow"
  cat "$TMP_DIR/gate.out"
  exit 1
fi
if grep -q "expected approval code" "$TMP_DIR/gate.out"; then
  echo "[TEST][FAIL] dry-run must not leak expected approval code"
  cat "$TMP_DIR/gate.out"
  exit 1
fi
if ! grep -q "approval challenge digest" "$TMP_DIR/gate.out"; then
  echo "[TEST][FAIL] dry-run should print challenge digest"
  cat "$TMP_DIR/gate.out"
  exit 1
fi

after_staging_hash="$(hash_file "$PROFILE_STAGING")"
after_prod_hash="$(hash_file "$PROFILE_PROD")"
after_log_hash="$(hash_file "$PROMO_LOG")"
if [[ "$before_staging_hash" != "$after_staging_hash" || "$before_prod_hash" != "$after_prod_hash" || "$before_log_hash" != "$after_log_hash" ]]; then
  echo "[TEST][FAIL] dry-run produced side effects (profiles/log changed)"
  echo "before_staging=$before_staging_hash after_staging=$after_staging_hash"
  echo "before_prod=$before_prod_hash after_prod=$after_prod_hash"
  echo "before_log=$before_log_hash after_log=$after_log_hash"
  exit 1
fi

set +e
"$ROOT/scripts/v2/p11_policy_promote_gate.sh" --from staging --to prod --approve --policy "$POLICY" >"$TMP_DIR/gate-blocked.out" 2>&1
rc=$?
set -e
if [[ "$rc" -ne 3 ]]; then
  echo "[TEST][FAIL] non-dry-run missing approval-code should be blocked with rc=3, got rc=$rc"
  cat "$TMP_DIR/gate-blocked.out"
  exit 1
fi

set +e
"$ROOT/scripts/v2/p11_policy_promote_gate.sh" --from staging --to prod --approve --approval-code deadbeef --policy "$POLICY" >"$TMP_DIR/gate-missing-approver.out" 2>&1
rc=$?
set -e
if [[ "$rc" -ne 3 ]] || ! grep -q "missing --approved-by" "$TMP_DIR/gate-missing-approver.out"; then
  echo "[TEST][FAIL] non-dry-run missing --approved-by should be blocked"
  cat "$TMP_DIR/gate-missing-approver.out"
  exit 1
fi

set +e
"$ROOT/scripts/v2/p11_policy_promote_gate.sh" --from staging --to prod --approve --approval-code deadbeef --approved-by alice --policy "$POLICY" >"$TMP_DIR/gate-missing-reviewer.out" 2>&1
rc=$?
set -e
if [[ "$rc" -ne 3 ]] || ! grep -q "missing --reviewed-by" "$TMP_DIR/gate-missing-reviewer.out"; then
  echo "[TEST][FAIL] non-dry-run missing --reviewed-by should be blocked"
  cat "$TMP_DIR/gate-missing-reviewer.out"
  exit 1
fi

set +e
"$ROOT/scripts/v2/p11_policy_promote_gate.sh" --from staging --to prod --approve --approval-code deadbeef --approved-by alice --reviewed-by alice --policy "$POLICY" >"$TMP_DIR/gate-same-identity.out" 2>&1
rc=$?
set -e
if [[ "$rc" -ne 3 ]] || ! grep -q "must be distinct" "$TMP_DIR/gate-same-identity.out"; then
  echo "[TEST][FAIL] non-dry-run same approver identity should be blocked"
  cat "$TMP_DIR/gate-same-identity.out"
  exit 1
fi

if grep -q "deadbeef" "$TMP_DIR/gate-same-identity.out"; then
  echo "[TEST][FAIL] gate output leaked approval code"
  cat "$TMP_DIR/gate-same-identity.out"
  exit 1
fi

echo "[TEST][PASS] p11 approval anti-leakage + dual-identity regression covered"
