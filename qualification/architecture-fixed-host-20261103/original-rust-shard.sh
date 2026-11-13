set -euo pipefail
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
    # The full workspace matrix includes both evaluation_sync_observation tests.
    # Run that target once in this matrix; a separate pre-run duplicated over ten
    # minutes of actual sync work and left the hosted 45-minute job incomplete.
    (
      trnm_model_receipt_root="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}"
      mkdir -p "$trnm_model_receipt_root"
      export TRNM_MODEL_COMPOSITION_VECTORS="$trnm_model_receipt_root/model-composition"
      test ! -e "$TRNM_MODEL_COMPOSITION_VECTORS"
      test ! -L "$TRNM_MODEL_COMPOSITION_VECTORS"
      mkdir "$TRNM_MODEL_COMPOSITION_VECTORS"
      export TRNM_MODEL_COMPOSITION_RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
      test -n "$TRNM_MODEL_COMPOSITION_RUN_ID"
      printf 'model-composition directory=%s run_id=%s\n' "$TRNM_MODEL_COMPOSITION_VECTORS" "$TRNM_MODEL_COMPOSITION_RUN_ID"
      export TRNM_AUTHENTICATED_STATE_VECTORS="$trnm_model_receipt_root/authenticated-state/native.json"
      test ! -e "$trnm_model_receipt_root/authenticated-state"
      test ! -L "$trnm_model_receipt_root/authenticated-state"
      mkdir "$trnm_model_receipt_root/authenticated-state"
      export TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR="$trnm_model_receipt_root/native-authenticated-state"
      test ! -e "$TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR"
      test ! -L "$TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR"
      export TRNM_AUTHENTICATED_MIGRATION_EXPORT="$trnm_model_receipt_root/authenticated-migration"
      test ! -e "$TRNM_AUTHENTICATED_MIGRATION_EXPORT"
      test ! -L "$TRNM_AUTHENTICATED_MIGRATION_EXPORT"
      export TRNM_ACCOUNT_MULTIPROOF_VECTORS="$trnm_model_receipt_root/account-multiproof/native.json"
      test ! -e "$trnm_model_receipt_root/account-multiproof"
      test ! -L "$trnm_model_receipt_root/account-multiproof"
      mkdir "$trnm_model_receipt_root/account-multiproof"
      export TRNM_OBLIGATION_RANGE_VECTORS="$trnm_model_receipt_root/obligation-range/native.json"
      test ! -e "$trnm_model_receipt_root/obligation-range"
      test ! -L "$trnm_model_receipt_root/obligation-range"
      mkdir "$trnm_model_receipt_root/obligation-range"
      export TRNM_ZERO_PAIRED_PREFIX_OUTPUT="$trnm_model_receipt_root/zero-paired-prefix"
      test ! -e "$TRNM_ZERO_PAIRED_PREFIX_OUTPUT"
      test ! -L "$TRNM_ZERO_PAIRED_PREFIX_OUTPUT"
      export TRNM_DAA_EVIDENCE_DIR="$trnm_model_receipt_root/daa-bounds"
      test ! -e "$TRNM_DAA_EVIDENCE_DIR"
      test ! -L "$TRNM_DAA_EVIDENCE_DIR"
      test ! -e "$trnm_model_receipt_root/workspace-tests.log"
      test ! -L "$trnm_model_receipt_root/workspace-tests.log"
      cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features 2>&1 | tee "$trnm_model_receipt_root/workspace-tests.log"
      unset TRNM_ZERO_PAIRED_PREFIX_OUTPUT
      python3 scripts/pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR" --expected-report-sha256 "$(sha256sum "$TRNM_DAA_EVIDENCE_DIR/daa-bounds.json" | cut -d ' ' -f 1)" > "$trnm_model_receipt_root/daa-bounds-python.json"
      python3 scripts/ci/test_pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR"
      unset TRNM_DAA_EVIDENCE_DIR
      python3 formal/pon-nakamoto-v1/test_zero_work.py --verify-prefix-export "$trnm_model_receipt_root/zero-paired-prefix" --output "$trnm_model_receipt_root/zero-paired-prefix-python"
      python3 formal/pon-nakamoto-v1/test_model_composition_oracle.py -v
      python3 formal/pon-nakamoto-v1/test_model_composition.py -v
      python3 formal/pon-nakamoto-v1/test_authenticated_state_archive_oracle.py -v
      python3 formal/pon-nakamoto-v1/authenticated_state_archive_oracle.py "$TRNM_AUTHENTICATED_STATE_VECTORS" "$trnm_model_receipt_root/authenticated-state/native.sqlite" --output "$trnm_model_receipt_root/authenticated-state/oracle.json"
      python3 formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py -v
      python3 formal/pon-nakamoto-v1/native_authenticated_storage_oracle.py "$TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR/native.json" "$TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR/native.sqlite" --output "$TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR/oracle.json"
      python3 formal/pon-nakamoto-v1/native_authenticated_storage_oracle.py "$TRNM_AUTHENTICATED_MIGRATION_EXPORT/native.json" "$TRNM_AUTHENTICATED_MIGRATION_EXPORT/native.sqlite" --migration-source "$TRNM_AUTHENTICATED_MIGRATION_EXPORT/source.sqlite" --output "$TRNM_AUTHENTICATED_MIGRATION_EXPORT/oracle.json"
      python3 formal/pon-nakamoto-v1/test_account_multiproof_oracle.py -v
      python3 formal/pon-nakamoto-v1/account_multiproof_oracle.py "$TRNM_ACCOUNT_MULTIPROOF_VECTORS" --output "$trnm_model_receipt_root/account-multiproof/oracle.json"
      python3 formal/pon-nakamoto-v1/test_obligation_range_oracle.py -v
      python3 formal/pon-nakamoto-v1/obligation_range_oracle.py "$TRNM_OBLIGATION_RANGE_VECTORS" --output "$trnm_model_receipt_root/obligation-range/oracle.json"
    )
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
