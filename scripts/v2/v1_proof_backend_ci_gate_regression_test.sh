#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/v1_proof_backend_ci_gate.sh"

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] v1 proof backend CI gate must exist and be executable: $GATE" >&2
  exit 1
fi

required_tests=(
  "tee_verifier_requires_cryptographic_backend_after_bound_envelope_validation"
  "tee_verifier_backend_unavailable_maps_to_indeterminate"
  "tee_verifier_valid_receipt_path_with_mock_backend"
  "tee_verifier_invalid_receipt_path_with_mock_backend"
  "zk_proof_without_crypto_backend_rejects_reveal_and_preserves_committed_state"
  "zk_verifier_unavailable_backend_maps_to_indeterminate"
  "zk_verifier_valid_proof_path_with_mock_backend"
  "zk_verifier_invalid_proof_path_with_mock_backend"
  "zk_verifier_requires_explicit_backend_when_feature_enabled"
  "registry_zk_vector_valid_payload_reaches_backend_path"
  "registry_zk_vector_invalid_payload_reaches_backend_rejection_path"
  "registry_zk_vector_fixture_style_payload_ignores_backend_metadata_variation"
)

for t in "${required_tests[@]}"; do
  if ! grep -Fq "$t" "$GATE"; then
    echo "[FAIL] v1 proof backend CI gate missing required test: $t" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CARGO_STUB="$TMP_DIR/cargo"
CALLS_LOG="$TMP_DIR/cargo.calls.log"
FAIL_TARGET="zk_verifier_unavailable_backend_maps_to_indeterminate"

cat >"$CARGO_STUB" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

log_file="${V1_GATE_CALLS_LOG:?missing calls log path}"
fail_target="${V1_GATE_FAIL_TARGET:-}"

echo "$*" >>"$log_file"

if [[ -n "$fail_target" ]] && [[ "$*" == *"$fail_target"* ]]; then
  echo "forced cargo failure for target: $fail_target" >&2
  exit 33
fi

exit 0
EOF
chmod +x "$CARGO_STUB"

POS_OUT="$TMP_DIR/positive.out"
PATH="$TMP_DIR:$PATH" V1_GATE_CALLS_LOG="$CALLS_LOG" "$GATE" >"$POS_OUT" 2>&1

if ! grep -Fq "[PASS] V1 proof backend CI gate" "$POS_OUT"; then
  echo "[FAIL] expected pass banner from v1 proof backend CI gate" >&2
  cat "$POS_OUT" >&2 || true
  exit 1
fi

for t in "${required_tests[@]}"; do
  if ! grep -Fq "$t" "$CALLS_LOG"; then
    echo "[FAIL] expected cargo invocation for required test: $t" >&2
    cat "$CALLS_LOG" >&2 || true
    exit 1
  fi
done

NEG_OUT="$TMP_DIR/negative.out"
if PATH="$TMP_DIR:$PATH" V1_GATE_CALLS_LOG="$CALLS_LOG" V1_GATE_FAIL_TARGET="$FAIL_TARGET" "$GATE" >"$NEG_OUT" 2>&1; then
  echo "[FAIL] v1 proof backend CI gate should fail-closed when one cargo subtest fails" >&2
  exit 1
fi

if ! grep -Fq "forced cargo failure for target: $FAIL_TARGET" "$NEG_OUT"; then
  echo "[FAIL] expected forced cargo failure marker in negative run" >&2
  cat "$NEG_OUT" >&2 || true
  exit 1
fi

echo "[PASS] v1_proof_backend_ci_gate_regression_test"
