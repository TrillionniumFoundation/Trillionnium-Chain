#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium"

cargo test -p trnm-pouw --lib registry_register_collapses_legacy_receipt_aliases_for_lookup
cargo test -p trnm-pouw --lib registry_registered_proof_types_are_normalized_and_sorted
cargo test -p trnm-pouw --lib registry_is_registered_for_reports_true_for_builtin_stack
cargo test -p trnm-pouw --lib registry_with_builtin_verifiers_surfaces_envelope_validation_failures
cargo test -p trnm-pouw --lib registry_ignores_empty_verifier_key_after_normalization
cargo test -p trnm-pouw --lib registry_aliases_stay_aligned_with_receipt_normalization_contract
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_version_suffixed_legacy_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_punctuated_legacy_receipt_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_dcap_quote_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_tdx_and_sev_snp_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_fullwidth_punctuation_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_horizontal_bar_delimited_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_unicode_minus_delimited_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_zero_width_separated_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_mongolian_vowel_separator_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_soft_hyphen_delimited_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_non_breaking_space_separated_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_ideographic_space_separated_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_narrow_and_figure_space_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_ogham_space_mark_aliases
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_fullwidth_version_digits
cargo test -p trnm-pouw --lib registry_is_registered_kind_accepts_multiline_whitespace_aliases
cargo test -p trnm-pouw --lib verify_bound_envelope_rejects_duplicate_task_id_binding_fail_closed
cargo test -p trnm-pouw --lib verify_bound_envelope_rejects_unexpected_worker_binding_without_worker_context_fail_closed

echo "[PASS] V1 proof registry contract gate"
