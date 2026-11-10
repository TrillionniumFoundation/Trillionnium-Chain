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
      export TRNM_JOINT_DAA_EVIDENCE_DIR="$trnm_model_receipt_root/joint-daa"
      test ! -e "$TRNM_JOINT_DAA_EVIDENCE_DIR"
      test ! -L "$TRNM_JOINT_DAA_EVIDENCE_DIR"
      export TRNM_WORK_SCHEDULE_RESEARCH_DIR="$trnm_model_receipt_root/branch-work-schedule"
      test ! -e "$TRNM_WORK_SCHEDULE_RESEARCH_DIR"
      test ! -L "$TRNM_WORK_SCHEDULE_RESEARCH_DIR"
      test ! -e "$trnm_model_receipt_root/workspace-tests.log"
      test ! -L "$trnm_model_receipt_root/workspace-tests.log"
      cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features 2>&1 | tee "$trnm_model_receipt_root/workspace-tests.log"
      unset TRNM_ZERO_PAIRED_PREFIX_OUTPUT
      python3 scripts/pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR" --expected-report-sha256 "$(sha256sum "$TRNM_DAA_EVIDENCE_DIR/daa-bounds.json" | cut -d ' ' -f 1)" > "$trnm_model_receipt_root/daa-bounds-python.json"
      python3 scripts/ci/test_pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR"
      unset TRNM_DAA_EVIDENCE_DIR
      for trnm_schedule_backend in pnh1-authenticated pgh2-growth; do
        trnm_schedule_dir="$TRNM_WORK_SCHEDULE_RESEARCH_DIR/$trnm_schedule_backend"
        trnm_schedule_digest="$(sha256sum "$trnm_schedule_dir/report.json" | cut -d ' ' -f 1)"
        python3 scripts/pon_branch_work_schedule_reader.py --raw-dir "$trnm_schedule_dir" --report-sha256 "$trnm_schedule_digest" > "$trnm_model_receipt_root/branch-work-schedule-$trnm_schedule_backend.json"
        python3 scripts/ci/test_pon_branch_work_schedule_reader.py --raw-dir "$trnm_schedule_dir" --report-sha256 "$trnm_schedule_digest" -v
      done
      unset TRNM_WORK_SCHEDULE_RESEARCH_DIR
      python3 scripts/pon_joint_daa_reader.py --raw-dir "$TRNM_JOINT_DAA_EVIDENCE_DIR/pnh1-authenticated" --expected-report-sha256 "$(sha256sum "$TRNM_JOINT_DAA_EVIDENCE_DIR/pnh1-authenticated/joint-daa.json" | cut -d ' ' -f 1)" > "$trnm_model_receipt_root/joint-daa-pnh1-python.json"
      python3 scripts/ci/test_pon_joint_daa_reader.py --raw-dir "$TRNM_JOINT_DAA_EVIDENCE_DIR/pnh1-authenticated"
      python3 scripts/pon_joint_daa_reader.py --raw-dir "$TRNM_JOINT_DAA_EVIDENCE_DIR/pgh2-growth" --expected-report-sha256 "$(sha256sum "$TRNM_JOINT_DAA_EVIDENCE_DIR/pgh2-growth/joint-daa.json" | cut -d ' ' -f 1)" > "$trnm_model_receipt_root/joint-daa-pgh2-python.json"
      python3 scripts/ci/test_pon_joint_daa_reader.py --raw-dir "$TRNM_JOINT_DAA_EVIDENCE_DIR/pgh2-growth"
      unset TRNM_JOINT_DAA_EVIDENCE_DIR
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
