#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

echo "[X2] settlement contract gate: dual-chain state machine + terminal payload invariants"

cargo test -p trnm-types settlement_state_machine_enforces_pending_terminal_model
cargo test -p trnm-types settlement_reapply_same_terminal_status_is_idempotent
cargo test -p trnm-types settlement_terminal_idempotent_reapply_ignores_blank_payload_overrides
cargo test -p trnm-types settlement_terminal_idempotent_reapply_rejects_conflicting_payload_override
cargo test -p trnm-types settlement_terminal_idempotent_reapply_accepts_whitespace_equivalent_payload
cargo test -p trnm-types settlement_terminal_idempotent_reapply_accepts_legacy_revert_reason_alias
cargo test -p trnm-types settlement_terminal_idempotent_reapply_still_rejects_height_regression
cargo test -p trnm-types settlement_revert_and_finalize_fields_are_mutually_exclusive
cargo test -p trnm-types settlement_pending_reapply_scrubs_terminal_payload_fields
cargo test -p trnm-types settlement_finalize_requires_non_empty_settlement_tx
cargo test -p trnm-types settlement_revert_requires_non_empty_reason
cargo test -p trnm-types settlement_terminal_payloads_are_trimmed_before_persisting
cargo test -p trnm-types settlement_revert_reason_normalizes_proof_adapter_aliases
cargo test -p trnm-types settlement_revert_reason_normalization_keeps_non_proof_reason
cargo test -p trnm-types settlement_revert_reason_reapply_accepts_equivalent_canonical_alias
cargo test -p trnm-types settlement_revert_reason_reapply_accepts_delimiter_variant_alias
cargo test -p trnm-types settlement_status_update_rejects_height_regression_without_side_effects
cargo test -p trnm-types settlement_evidence_path_tracks_terminal_state_machine_outcome
cargo test -p trnm-types settlement_evidence_path_sanitizes_windows_separators_and_control_whitespace
cargo test -p trnm-types settlement_evidence_path_sanitizes_unicode_whitespace_segments
cargo test -p trnm-types settlement_evidence_path_sanitizes_colon_for_cross_platform_filesystem_safety
cargo test -p trnm-types settlement_evidence_path_avoids_windows_reserved_device_names
cargo test -p trnm-types settlement_evidence_path_avoids_windows_reserved_device_names_with_extension_alias

echo "[X2][PASS] settlement contract gate"
