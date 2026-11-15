#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"
bash scripts/project-preflight.sh

exact_native_test() {
  local cell_test_log
  cell_test_log="$(mktemp)"
  cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
    -p "$1" --lib "$2" -- --exact --nocapture 2>&1 | tee "$cell_test_log"
  python3 scripts/ci/check_required_native_test.py "$cell_test_log" --test "$2"
  rm -f "$cell_test_log"
}

case "${1:?select native, checks or clippy}" in
  native)
    cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
      -p trnm-data-availability --all-targets --all-features
    cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
      -p trnm-data-availability --all-features --doc
    cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
      -p trnm-service-settlement --lib
    for test in \
      continuity_v1::capacity_range_tests::capacity_ranges_match_full_state_and_authenticated_monetary_sources \
      continuity_v1::capacity_range_tests::capacity_ranges_preserve_first_error_and_exact_account_access_order \
      continuity_v1::capacity_range_tests::ordinary_capacity_keeps_full_key_limit_and_profile_error_precedence \
      pon_executor::prefix_scan_tests::funds_ranges_keep_complete_supply_and_malformed_namespace_boundaries \
      pon_executor::prefix_scan_tests::funds_ranges_keep_global_first_error_before_later_overflow_or_bad_types; do
      exact_native_test trnm-mvcc-fee "$test"
    done
    cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
      -p trnm-pon-node --lib store::storage_service
    for test in \
      store::growth::tests::native_growth_v2_activation_cancellation_precedes_sql_even_for_noop_or_unknown_target \
      store::growth::tests::native_growth_v2_activation_rechecks_foreign_epoch_after_transaction_begin; do
      exact_native_test trnm-pon-node "$test"
    done
    ;;
  checks)
    cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
    python3 scripts/refresh_distributed_source_inventory.py --check
    python3 scripts/ci/check_pq_research_integration.py
    python3 scripts/ci/check_ci_contract.py
    python3 -m unittest scripts.ci.test_llm_cell_provider_ready \
      scripts.ci.test_llm_cell_handoff_deadline -v
    for suite in test_ci_source_integrity.py test_pq_research_integration.py \
      test_pq_chain_claim_guard.py test_pq_authority_surface_scan.py; do
      python3 -m unittest discover -s scripts/ci -p "$suite" -v
    done
    python3 -m unittest discover -s formal/pon-nakamoto-v1 \
      -p test_cell_dependency_closure.py -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 \
      -p test_model_release_root.py -v
    python3 scripts/ci/check_repository.py
    cargo metadata --manifest-path trillionnium/Cargo.toml --locked --offline \
      --format-version 1
    ;;
  clippy)
    cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline \
      --workspace --all-targets -- -D warnings
    ;;
  *) exit 2 ;;
esac
