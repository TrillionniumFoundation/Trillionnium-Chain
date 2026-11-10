set -euo pipefail
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
    python3 scripts/ci/run_supply_chain.py
    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --doc --all-features
    cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
    (
      trnm_native_receipt_root="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}"
      mkdir -p "$trnm_native_receipt_root"
      test ! -e "$trnm_native_receipt_root/native-capacity-release.log"
      test ! -L "$trnm_native_receipt_root/native-capacity-release.log"
      cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-capacity-release.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-capacity-release.log" --test account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover
      test ! -e "$trnm_native_receipt_root/native-growth-reference-release.log"
      test ! -L "$trnm_native_receipt_root/native-growth-reference-release.log"
      test ! -e "$trnm_native_receipt_root/native-growth-reference"
      test ! -L "$trnm_native_receipt_root/native-growth-reference"
      TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY="$trnm_native_receipt_root/native-growth-reference" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-growth-reference-release.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-growth-reference-release.log" --test store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen
      test ! -e "$trnm_native_receipt_root/native-growth-reference/readback.json"
      test ! -L "$trnm_native_receipt_root/native-growth-reference/readback.json"
      python3 -B formal/pon-nakamoto-v1/check_gsc2_native_readback.py --artifact-dir "$trnm_native_receipt_root/native-growth-reference" --source-root "$(pwd -P)" --minimum-accounts 65537 > "$trnm_native_receipt_root/native-growth-reference/readback.json"
      test ! -e "$trnm_native_receipt_root/native-growth-v2-release.log"
      test ! -L "$trnm_native_receipt_root/native-growth-v2-release.log"
      test ! -e "$trnm_native_receipt_root/native-growth-v2"
      test ! -L "$trnm_native_receipt_root/native-growth-v2"
      TRNM_NATIVE_GROWTH_V2_EXPORT_DIR="$trnm_native_receipt_root/native-growth-v2" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-growth-v2-release.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-growth-v2-release.log" --test store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen
      test -s "$trnm_native_receipt_root/native-growth-v2/native.json"
      test ! -L "$trnm_native_receipt_root/native-growth-v2/native.json"
      test ! -e "$trnm_native_receipt_root/native-account-verification-cost"
      test ! -L "$trnm_native_receipt_root/native-account-verification-cost"
      test ! -e "$trnm_native_receipt_root/native-account-verification-cost.log"
      test ! -L "$trnm_native_receipt_root/native-account-verification-cost.log"
      TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY="$trnm_native_receipt_root/native-account-verification-cost" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-account-verification-cost.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-account-verification-cost.log" --test account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost
    )
