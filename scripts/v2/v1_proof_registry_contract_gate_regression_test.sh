#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/v1_proof_registry_contract_gate.sh"

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] v1 proof registry gate must exist and be executable: $GATE" >&2
  exit 1
fi

required_tests=(
  "registry_register_collapses_legacy_receipt_aliases_for_lookup"
  "registry_registered_proof_types_are_normalized_and_sorted"
  "registry_is_registered_for_reports_true_for_builtin_stack"
  "registry_with_builtin_verifiers_surfaces_envelope_validation_failures"
  "registry_ignores_empty_verifier_key_after_normalization"
  "registry_aliases_stay_aligned_with_receipt_normalization_contract"
  "registry_is_registered_kind_accepts_version_suffixed_legacy_aliases"
  "registry_is_registered_kind_accepts_punctuated_legacy_receipt_aliases"
  "registry_is_registered_kind_accepts_dcap_quote_aliases"
  "registry_is_registered_kind_accepts_tdx_and_sev_snp_aliases"
  "registry_is_registered_kind_accepts_fullwidth_punctuation_aliases"
  "registry_is_registered_kind_accepts_horizontal_bar_delimited_aliases"
  "registry_is_registered_kind_accepts_unicode_minus_delimited_aliases"
  "registry_is_registered_kind_accepts_zero_width_separated_aliases"
  "registry_is_registered_kind_accepts_soft_hyphen_delimited_aliases"
  "registry_is_registered_kind_accepts_non_breaking_space_separated_aliases"
  "registry_is_registered_kind_accepts_ideographic_space_separated_aliases"
  "registry_is_registered_kind_accepts_narrow_and_figure_space_aliases"
  "registry_is_registered_kind_accepts_ogham_space_mark_aliases"
  "registry_is_registered_kind_accepts_fullwidth_version_digits"
)

for t in "${required_tests[@]}"; do
  if ! grep -Fq "$t" "$GATE"; then
    echo "[FAIL] v1 proof registry gate missing required test: $t" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CARGO_STUB="$TMP_DIR/cargo"
CALLS_LOG="$TMP_DIR/cargo.calls.log"
FAIL_TARGET="registry_is_registered_kind_accepts_unicode_minus_delimited_aliases"

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

if ! grep -Fq "[PASS] V1 proof registry contract gate" "$POS_OUT"; then
  echo "[FAIL] expected pass banner from v1 proof registry gate" >&2
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
  echo "[FAIL] v1 proof registry gate should fail-closed when one cargo subtest fails" >&2
  exit 1
fi

if ! grep -Fq "forced cargo failure for target: $FAIL_TARGET" "$NEG_OUT"; then
  echo "[FAIL] expected forced cargo failure marker in negative run" >&2
  cat "$NEG_OUT" >&2 || true
  exit 1
fi

echo "[PASS] v1_proof_registry_contract_gate_regression_test"
