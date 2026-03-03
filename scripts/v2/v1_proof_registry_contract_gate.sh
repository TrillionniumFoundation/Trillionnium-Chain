#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

cargo test -p trnm-pouw registry_register_collapses_legacy_receipt_aliases_for_lookup
cargo test -p trnm-pouw registry_registered_proof_types_are_normalized_and_sorted
cargo test -p trnm-pouw registry_is_registered_for_reports_true_for_builtin_stack
cargo test -p trnm-pouw registry_aliases_stay_aligned_with_receipt_normalization_contract
cargo test -p trnm-pouw registry_is_registered_kind_accepts_version_suffixed_legacy_aliases
cargo test -p trnm-pouw registry_is_registered_kind_accepts_zero_width_separated_aliases
cargo test -p trnm-pouw registry_is_registered_kind_accepts_non_breaking_space_separated_aliases
cargo test -p trnm-pouw registry_is_registered_kind_accepts_ideographic_space_separated_aliases

echo "[PASS] V1 proof registry contract gate"
