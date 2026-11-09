#!/usr/bin/env python3
"""Check the deliberately fixed hosted-CI structure; this does not execute its lanes."""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
import tomllib

from check_cross_arch_cost import (COST_JOB_TIMEOUT_MINUTES, COST_JOB_OVERHEAD_SECONDS,
                                   cost_job_budget_seconds)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = '.github/workflows/trnm-required-baseline.yml'
CHECKOUT = 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
DOWNLOAD = 'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0'
RUNTIME_RELEASE_REQUIREMENT = r'''packaging==26.3 \
    --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c'''
RUNTIME_RELEASE_COMMAND = '    "${TRNM_RUNTIME_RELEASE_PYTHON:-python3}" scripts/test_llm_runtime_release.py\n'
RUNTIME_RELEASE_PYTHON = r'''      - name: Install isolated runtime material verifier dependency
        shell: bash
        run: |
          set -euo pipefail
          python3 -m venv "$RUNNER_TEMP/runtime-release-env"
          "$RUNNER_TEMP/runtime-release-env/bin/python" -m pip --isolated install --disable-pip-version-check --only-binary=:all: --require-hashes --report "$RUNNER_TEMP/ci-observations/runtime-release-dependencies.json" -r scripts/ci/runtime-release-requirements.txt
          printf 'TRNM_RUNTIME_RELEASE_PYTHON=%s/runtime-release-env/bin/python\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
'''
MERGE_RUNTIME_RELEASE_PYTHON = RUNTIME_RELEASE_PYTHON.replace(
    '        shell: bash\n', "        if: matrix.lane == 'repository-truth'\n        shell: bash\n")
SIGNED_STATE_PYTHON = '''      - name: Install isolated signed-state oracle Python environment
        run: |
          python3 -m venv "$RUNNER_TEMP/pon-state-env"
          "$RUNNER_TEMP/pon-state-env/bin/python" -m pip install --disable-pip-version-check --only-binary=:all: -r formal/pon-nakamoto-v1/requirements.txt
          echo "$RUNNER_TEMP/pon-state-env/bin" >> "$GITHUB_PATH"
'''
ZERO_RUN_STEP = '''      - name: Execute native zero-matrix locality costs
        if: always()
        run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite zero-locality --zero-version 2
'''
ZERO_COMPARE_STEP = '''      - name: Check zero-matrix streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-zero-locality-comparison.json" --suite zero-locality --zero-version 2
'''
ONE_ZERO_RUN_STEP = '''      - name: Execute native one-zero rank-one locality costs
        if: always()
        run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite one-zero-locality
'''
ONE_ZERO_COMPARE_STEP = '''      - name: Check one-zero rank-one streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-one-zero-locality-comparison.json" --suite one-zero-locality
'''
MAINTENANCE_RUN_STEP = '''      - name: Execute native fixed maintenance producer and preparation costs
        if: always()
        run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite maintenance-paired
'''
MAINTENANCE_COMPARE_STEP = '''      - name: Check fixed maintenance streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-maintenance-comparison.json" --suite maintenance-paired
'''
REJECTION_RUN_STEP = '''      - name: Execute native legal and late-rejection verifier costs
        if: always()
        run: python3 scripts/pon_work_rejection_report.py --run --out "$TRNM_CI_RECEIPT_DIR/work-rejection"
'''
REJECTION_COMPARE_STEP = '''      - name: Check actual rejection stages and paired native architectures
        if: always()
        run: python3 scripts/pon_work_rejection_report.py --compare "$RUNNER_TEMP/cost-inputs/cost-x64-$TRNM_EXPECTED_SOURCE_SHA-$GITHUB_RUN_ATTEMPT/work-rejection" "$RUNNER_TEMP/cost-inputs/cost-arm64-$TRNM_EXPECTED_SOURCE_SHA-$GITHUB_RUN_ATTEMPT/work-rejection" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --expected-run "$GITHUB_RUN_ID" --expected-attempt "$GITHUB_RUN_ATTEMPT" --out "$RUNNER_TEMP/ci-observations/work-rejection-comparison"
'''
W1_REUSE_V3_JOB = r'''  cross-arch-w1-reuse-v3:
    name: W1 actual reuse V3 (${{ matrix.arch }}, ${{ matrix.source }})
    if: github.event_name == 'pull_request'
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 155
    strategy:
      fail-fast: false
      matrix:
        arch: [x64, arm64]
        source: [head, prospective-merge]
        include:
          - arch: x64
            runner: ubuntu-24.04
          - arch: arm64
            runner: ubuntu-24.04-arm
    env:
      TRNM_COST_RUNNER_LABEL: ${{ matrix.runner }}
      TRNM_COST_SOURCE_KIND: ${{ matrix.source }}
      TRNM_EXPECTED_SOURCE_SHA: ${{ matrix.source == 'head' && github.event.pull_request.head.sha || github.sha }}
      TRNM_EXPECTED_CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}
      TRNM_EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha }}
    steps:
      - name: Checkout exact candidate
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}
          fetch-depth: 0
          persist-credentials: false
      - name: Verify V3 exact source and ordered merge before execution
        shell: bash
        run: |
          set -euo pipefail
          args=(--kind "$TRNM_COST_SOURCE_KIND" --expected-head "$TRNM_EXPECTED_CANDIDATE_SHA")
          if test "$TRNM_COST_SOURCE_KIND" = prospective-merge; then
            args+=(--expected-base "$TRNM_EXPECTED_BASE_SHA" --expected-merge "$TRNM_EXPECTED_SOURCE_SHA")
          fi
          python3 scripts/ci/verify_ci_source.py "${args[@]}" --output "$RUNNER_TEMP/ci-observations/source-before.json"
      - name: Check original repository boundary before native V3 build
        run: bash scripts/project-preflight.sh --audit
      - name: Set isolated Cargo paths after runner allocation
        shell: bash
        run: |
          set -euo pipefail
          printf 'CARGO_HOME=%s/cargo-%s\n' "$RUNNER_TEMP" "$GITHUB_JOB" >> "$GITHUB_ENV"
          printf 'CARGO_TARGET_DIR=%s/target-%s\n' "$RUNNER_TEMP" "$GITHUB_JOB" >> "$GITHUB_ENV"
          printf 'TRNM_CI_RECEIPT_DIR=%s/ci-observations\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
      - name: Install pinned native release compiler
        run: rustup toolchain install 1.95.0 --profile minimal
      - name: Install matching native formatter
        run: rustup component add --toolchain 1.95.0 rustfmt
      - name: Execute the complete native W1 actual reuse V3 grid
        run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_w1_reused_cost_v3.py --arch "${{ matrix.arch }}"
      - name: Verify V3 exact source and ordered merge after execution
        if: always()
        shell: bash
        run: |
          set -euo pipefail
          args=(--kind "$TRNM_COST_SOURCE_KIND" --expected-head "$TRNM_EXPECTED_CANDIDATE_SHA")
          if test "$TRNM_COST_SOURCE_KIND" = prospective-merge; then
            args+=(--expected-base "$TRNM_EXPECTED_BASE_SHA" --expected-merge "$TRNM_EXPECTED_SOURCE_SHA")
          fi
          python3 scripts/ci/verify_ci_source.py "${args[@]}" --output "$RUNNER_TEMP/ci-observations/source-after.json"
      - name: Retain V3 costs including all failed observations
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: w1-reuse-v3-${{ matrix.source }}-${{ matrix.arch }}-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/ci-observations/
          if-no-files-found: error
          retention-days: 30
'''
CONTINUITY_BUILD = '    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee --examples\n'
CONTINUITY_ORIGINAL = '    TRNM_CONTINUITY_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_vectors")" python3 formal/pon-nakamoto-v1/test_continuity.py -v\n'
CONTINUITY_TRANSITIONS = '    TRNM_CONTINUITY_TRANSITIONS_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_transition_vectors")" python3 formal/pon-nakamoto-v1/test_continuity_transitions.py -v\n'
PAIRED_WORK_ORACLE = '    TRNM_PAIRED_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_paired_io")" TRNM_PAIRED_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/paired-work" python3 formal/pon-nakamoto-v1/test_paired_work.py -v\n'
ZERO_WORK_ORACLE = '    TRNM_ZERO_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" TRNM_ZERO_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/zero-work" python3 formal/pon-nakamoto-v1/test_zero_work.py -v\n'
MANDATORY_UNITS_NATIVE = '    MU1_NATIVE_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" MU1_NATIVE_PREPARED="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" python3 formal/pon-nakamoto-v1/mandatory_units_tests.py -v\n'
WORK_LIFECYCLE_NATIVE = ('    WLC_NATIVE_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" WLC_NATIVE_PQ="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pq_message_oracle")" python3 formal/pon-nakamoto-v1/work_lifecycle_tests.py -v\n'
                         '    python3 formal/pon-nakamoto-v1/work_lifecycle_observe.py --native-work "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" --native-pq "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pq_message_oracle")" --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/work-lifecycle"\n')
NATIVE_OWNER_SCORE_BRIDGE = ('    TRNM_NATIVE_OWNER_OBSERVATION="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/native_owner_observation_v1")" TRNM_NATIVE_OWNER_RECORD_DIR="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-score-bridge" python3 formal/pon-nakamoto-v1/test_native_owner_score_bridge.py -v\n'
                             '    python3 formal/pon-nakamoto-v1/certificate_observability_evidence.py --native-owner-json "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-score-bridge/native.json" --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-score-bridge/observability.json"\n')
LIFECYCLE_QUERY_NATIVE = '    LQC_NATIVE_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" LQC_NATIVE_PREPARED="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" python3 formal/pon-nakamoto-v1/lifecycle_query_evidence.py --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/lifecycle-query"\n'
CERTIFICATE_COMPOSITION_TESTS = "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'certificate_composition_tests.py' -v\n"
NATIVE_OWNER_JOURNAL = ('    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_owner_journal\n    "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/native_owner_journal_v1")" "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal"\n    NATIVE_OWNER_JOURNAL_RUN="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/run.json" python3 -m unittest discover -s formal/pon-nakamoto-v1 -p \'test_native_owner_journal.py\' -v\n    python3 formal/pon-nakamoto-v1/native_owner_journal.py --run "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/run.json" --output "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/checked.json"\n'
                        + CERTIFICATE_COMPOSITION_TESTS
                        + '    python3 formal/pon-nakamoto-v1/certificate_composition_evidence.py --native-run "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/run.json" --output-dir "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/certificate-composition"\n')
NATIVE_RISK_LEDGER = '    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_risk_ledger\n    "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/native_risk_ledger_v1")" "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger"\n    NATIVE_RISK_LEDGER_RUN="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger/run.json" python3 -m unittest discover -s formal/pon-nakamoto-v1 -p \'test_native_risk_ledger.py\' -v\n    python3 formal/pon-nakamoto-v1/native_risk_ledger.py --run "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger/run.json" --output "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger/checked.json"\n'
WORK_NATIVE_MODEL_COMMANDS = (
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_probability_contract.py' -v",
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_feasibility.py' -v",
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential.py' -v",
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential_independent.py' -v",
    'python3 formal/pon-nakamoto-v1/fixed_probability_contract.py',
    'python3 formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py --check',
    'python3 formal/pon-nakamoto-v1/stateful_tail.py',
    'python3 formal/pon-nakamoto-v1/residual_grover.py',
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_fork_witness.py' -v",
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_execution_certificate.py' -v",
    'python3 formal/pon-nakamoto-v1/mandatory_units_tests.py ContextContractTests QueryCertificateTests -v',
    'python3 formal/pon-nakamoto-v1/certificate_observability_tests.py -v',
    'python3 formal/pon-nakamoto-v1/lifecycle_query_tests.py -v',
    'python3 formal/pon-nakamoto-v1/finite_joint_state_tests.py -v',
    'python3 formal/pon-nakamoto-v1/test_joint_consensus_boundaries.py -v',
    'python3 formal/pon-nakamoto-v1/certificate_event_coverage_tests.py -v',
)

# Anchor these controls at the start of the lane. Presence/count alone accepts
# a false branch or an if-condition that suppresses Bash's errexit behavior.
# The outer lane dispatch is checked independently below.
CREDIT_MODEL_COMMANDS = (
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_envelope_contract.py' -v",
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_normalized_search_cost.py' -v",
)
CREDIT_MODEL_PREFIX = (
    "    bash scripts/project-preflight.sh --audit\n"
    "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_envelope_contract.py' -v\n"
    "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_normalized_search_cost.py' -v\n"
)
MODEL_WINDOW_ORACLE = '    python3 formal/pon-nakamoto-v1/test_model_window_history.py -v\n'
EVALUATION_QUORUM_ORACLE = ('    python3 formal/pon-nakamoto-v1/test_native_evaluation_quorum_oracle.py -v\n'
                          '    python3 formal/pon-nakamoto-v1/native_evaluation_quorum_oracle.py\n')
MODEL_EVOLUTION_ORACLES = ('    python3 formal/pon-nakamoto-v1/test_model_evolution_oracle.py -v\n'
                          '    python3 formal/pon-nakamoto-v1/test_model_task_windows_oracle.py -v\n')
DEMAND_UPGRADE_CONTROLS = ('    python3 formal/pon-nakamoto-v1/test_demand_evidence.py -v\n'
                         '    python3 formal/pon-nakamoto-v1/test_upgrade_policy.py -v\n')
NATIVE_DEMAND_CONTRACTS = '    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test no_gain_fees --test funded_service_contract --test native_demand_evidence --test native_task_operation_v2 --test native_active_anchor --all-features -- --test-threads=1\n'
COST_BOUNDARY_READERS = ('    python3 scripts/ci/test_pon_w1_budget_readers.py --raw-dir evidence/pon-upgrade-implementation-20261018/native-rounds/chain-p0-native-54\n'
                         '    python3 scripts/ci/test_pon_public_v3_phase_read.py\n'
                         '    python3 scripts/ci/test_pon_public_v3_policy_read.py\n'
                         '    python3 scripts/ci/test_pon_v3_cookie_cpu_study.py\n'
                         '    python3 scripts/ci/test_run_pon_w1_native_campaign.py\n')
CURRENT_READER_COMMANDS = (
    'python3 scripts/ci/test_read_validated_business_goodput.py',
    'python3 scripts/ci/test_pon_w1_cost_matrix_reader.py',
    'python3 scripts/ci/test_pon_w1_reused_cost_reader_v3.py',
    'python3 scripts/ci/test_run_w1_reused_cost_v3.py',
    'python3 scripts/ci/test_w1_lifecycle_cost_v4.py',
    'python3 scripts/ci/test_pon_public_v3_policy_read.py',
    'python3 scripts/ci/test_llm_cell_handoff_deadline.py',
    'python3 scripts/ci/test_run_legacy_reorg_root_abba.py',
)
W1_LIFECYCLE_NATIVE_CONTROLS = 'cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example pon_w1_lifecycle_cost_v4'
PROOF_LATENCY_READER_COMMANDS = (
    'python3 scripts/ci/test_pon_proof_latency.py',
    'python3 scripts/ci/test_w1_proof_latency_readback.py',
)
LLM_RUNTIME_TESTS = (
    '    python3 scripts/test_llm_runtime_rss_owner.py\n'
    '    python3 scripts/test_llm_runtime_exit_observation.py\n'
    '    python3 scripts/test_llm_runtime_stop.py\n'
    '    python3 scripts/test_llm_inherited_runtime.py\n'
    '    python3 scripts/test_llm_neural_read_worker.py\n'
    '    python3 scripts/test_llm_python_runtime_contract.py\n'
)
ORIGINAL_CAMPAIGN_READER = r'''    python3 scripts/ci/test_read_original_native_campaign.py \
      --artifact-dir evidence/pon-upgrade-implementation-20261018/native-rounds/chain-pr327-original-campaign-39694587963 \
      --expected-manifest-sha256 12406cc156e57c130fa14af2b50b386031ec3640ce7f0234ed5bc9f0a700aac3 \
      --expected-head 9e705ccf75b7318dcc4bda4815956f58beb10e72 \
      --expected-tree 521ae87a28060d545979069b189eebbc74a71fd8 --retained-subset
'''
NODE_EXAMPLE_BUILD = '    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --bins --examples\n'
ACCOUNT_ARCHIVE_ORACLE = ('    python3 formal/pon-nakamoto-v1/test_account_archive_oracle.py -v\n'
                          '    python3 scripts/ci/run_account_archive_conformance.py\n')
ACCOUNT_EXECUTION_ORACLE = ('    python3 formal/pon-nakamoto-v1/test_account_execution_oracle.py -v\n'
                            '    python3 formal/pon-nakamoto-v1/test_state_witness_oracle.py -v\n'
                            '    python3 scripts/ci/run_account_execution_conformance.py\n')
GSC2_SYNTHETIC_ORACLE = '    python3 -B formal/pon-nakamoto-v1/test_gsc2_native_readback_synthetic.py --source-root "$(pwd -P)"\n'
NATIVE_GROWTH_RELEASE_BLOCK = '''      test ! -e "$trnm_native_receipt_root/native-growth-reference-release.log"
      test ! -L "$trnm_native_receipt_root/native-growth-reference-release.log"
      test ! -e "$trnm_native_receipt_root/native-growth-reference"
      test ! -L "$trnm_native_receipt_root/native-growth-reference"
      TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY="$trnm_native_receipt_root/native-growth-reference" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-growth-reference-release.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-growth-reference-release.log" --test store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen
      test ! -e "$trnm_native_receipt_root/native-growth-reference/readback.json"
      test ! -L "$trnm_native_receipt_root/native-growth-reference/readback.json"
      python3 -B formal/pon-nakamoto-v1/check_gsc2_native_readback.py --artifact-dir "$trnm_native_receipt_root/native-growth-reference" --source-root "$(pwd -P)" --minimum-accounts 65537 > "$trnm_native_receipt_root/native-growth-reference/readback.json"
'''
NATIVE_GROWTH_V2_RELEASE_BLOCK = '''      test ! -e "$trnm_native_receipt_root/native-growth-v2-release.log"
      test ! -L "$trnm_native_receipt_root/native-growth-v2-release.log"
      test ! -e "$trnm_native_receipt_root/native-growth-v2"
      test ! -L "$trnm_native_receipt_root/native-growth-v2"
      TRNM_NATIVE_GROWTH_V2_EXPORT_DIR="$trnm_native_receipt_root/native-growth-v2" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-growth-v2-release.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-growth-v2-release.log" --test store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen
      test -s "$trnm_native_receipt_root/native-growth-v2/native.json"
      test ! -L "$trnm_native_receipt_root/native-growth-v2/native.json"
'''
RUST_ALL_TARGETS = 'cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features'
RUST_DOCS = '    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --doc --all-features\n'
RUST_CLIPPY = '    cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings\n'
MODEL_OBSERVATION_BLOCK = '''    (
      trnm_model_receipt_root="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}"
      mkdir -p "$trnm_model_receipt_root"
      export TRNM_MODEL_COMPOSITION_VECTORS="$trnm_model_receipt_root/model-composition"
      test ! -e "$TRNM_MODEL_COMPOSITION_VECTORS"
      test ! -L "$TRNM_MODEL_COMPOSITION_VECTORS"
      mkdir "$TRNM_MODEL_COMPOSITION_VECTORS"
      export TRNM_MODEL_COMPOSITION_RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
      test -n "$TRNM_MODEL_COMPOSITION_RUN_ID"
      printf 'model-composition directory=%s run_id=%s\\n' "$TRNM_MODEL_COMPOSITION_VECTORS" "$TRNM_MODEL_COMPOSITION_RUN_ID"
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
'''
NATIVE_RELEASE_BLOCK = '''    (
      trnm_native_receipt_root="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}"
      mkdir -p "$trnm_native_receipt_root"
      test ! -e "$trnm_native_receipt_root/native-capacity-release.log"
      test ! -L "$trnm_native_receipt_root/native-capacity-release.log"
      cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-capacity-release.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-capacity-release.log" --test account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover
''' + NATIVE_GROWTH_RELEASE_BLOCK + NATIVE_GROWTH_V2_RELEASE_BLOCK + '''\
      test ! -e "$trnm_native_receipt_root/native-account-verification-cost"
      test ! -L "$trnm_native_receipt_root/native-account-verification-cost"
      test ! -e "$trnm_native_receipt_root/native-account-verification-cost.log"
      test ! -L "$trnm_native_receipt_root/native-account-verification-cost.log"
      TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY="$trnm_native_receipt_root/native-account-verification-cost" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-account-verification-cost.log"
      python3 scripts/ci/check_required_native_test.py "$trnm_native_receipt_root/native-account-verification-cost.log" --test account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost
    )
'''

# Freeze the complete straight-line lane independently of the file being checked.
# Presence/count checks alone also match commands skipped or swallowed by shell
# control flow. Keep their specific diagnostics before the full-lane comparison.
PQ_MIGRATION_CONFORMANCE_PREFIX = '''    # Actual offline signatures/SQLite and public fixture arithmetic only.
    # These checks grant no historical ownership, seed-proof or cutover authority.
    PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_account_migration.py' -v
    PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_migration_journal_owner.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_seed_relation_vectors_v1.py' -v
'''
PROTOCOL_CONTRACT_BLOCK = PQ_MIGRATION_CONFORMANCE_PREFIX + '''    python3 scripts/ci/run_from_zero_host.py -- python3 scripts/ci/run_from_zero_native.py --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/from-zero-native"
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example pon_w1_lifecycle_cost_v4
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives -p trnm-checkpoint-types -p trnm-verification-profiles --all-targets --all-features
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol --all-targets --all-features
    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee --examples
    TRNM_CONTINUITY_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_vectors")" python3 formal/pon-nakamoto-v1/test_continuity.py -v
    TRNM_CONTINUITY_TRANSITIONS_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_transition_vectors")" python3 formal/pon-nakamoto-v1/test_continuity_transitions.py -v
    TRNM_PAIRED_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_paired_io")" TRNM_PAIRED_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/paired-work" python3 formal/pon-nakamoto-v1/test_paired_work.py -v
    TRNM_ZERO_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" TRNM_ZERO_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/zero-work" python3 formal/pon-nakamoto-v1/test_zero_work.py -v
    MU1_NATIVE_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" MU1_NATIVE_PREPARED="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" python3 formal/pon-nakamoto-v1/mandatory_units_tests.py -v
    WLC_NATIVE_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" WLC_NATIVE_PQ="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pq_message_oracle")" python3 formal/pon-nakamoto-v1/work_lifecycle_tests.py -v
    python3 formal/pon-nakamoto-v1/work_lifecycle_observe.py --native-work "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" --native-pq "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pq_message_oracle")" --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/work-lifecycle"
    LQC_NATIVE_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io")" LQC_NATIVE_PREPARED="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" python3 formal/pon-nakamoto-v1/lifecycle_query_evidence.py --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/lifecycle-query"
    TRNM_GROUPED_NATIVE="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_routed_int257_grouped")" python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_grouped*.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fresh_work_query_floor_v0.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fresh_work_resource_transfer_v0.py' -v
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-transport proof_admission --all-targets
    python3 formal/pon-nakamoto-v1/test_contracts.py
    python3 formal/pon-nakamoto-v1/test_invariants.py
    cargo fetch --locked --manifest-path trillionnium/Cargo.toml
    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --bins --examples
    python3 formal/pon-nakamoto-v1/test_account_archive_oracle.py -v
    python3 scripts/ci/run_account_archive_conformance.py
    python3 formal/pon-nakamoto-v1/test_account_execution_oracle.py -v
    python3 formal/pon-nakamoto-v1/test_state_witness_oracle.py -v
    python3 scripts/ci/run_account_execution_conformance.py
    python3 -B formal/pon-nakamoto-v1/test_gsc2_native_readback_synthetic.py --source-root "$(pwd -P)"
    TRNM_NATIVE_OWNER_OBSERVATION="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/native_owner_observation_v1")" TRNM_NATIVE_OWNER_RECORD_DIR="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-score-bridge" python3 formal/pon-nakamoto-v1/test_native_owner_score_bridge.py -v
    python3 formal/pon-nakamoto-v1/certificate_observability_evidence.py --native-owner-json "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-score-bridge/native.json" --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-score-bridge/observability.json"
    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_owner_journal
    "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/native_owner_journal_v1")" "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal"
    NATIVE_OWNER_JOURNAL_RUN="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/run.json" python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_owner_journal.py' -v
    python3 formal/pon-nakamoto-v1/native_owner_journal.py --run "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/run.json" --output "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/checked.json"
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'certificate_composition_tests.py' -v
    python3 formal/pon-nakamoto-v1/certificate_composition_evidence.py --native-run "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-owner-journal/run.json" --output-dir "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/certificate-composition"
    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_risk_ledger
    "$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/native_risk_ledger_v1")" "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger"
    NATIVE_RISK_LEDGER_RUN="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger/run.json" python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_risk_ledger.py' -v
    python3 formal/pon-nakamoto-v1/native_risk_ledger.py --run "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger/run.json" --output "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/native-risk-ledger/checked.json"
    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test qualified_tasks --test protected_ingress --test task_lifecycle --test task_lifecycle_v3 --test task_lifecycle_v4 --test public_evaluation --test public_intake_v2 --test public_cli --test local_mempool --test pool_mining --test public_pool_v3 --test public_pool_cli --test public_v3_observer --test pinned_peer_polling --test ancestry_long_sync --test distributed_roles --test cell_native_v1 --test grouped_fresh_admission_v0 --test grouped_verification_authority_v0
    TRNM_DISTRIBUTED_TEST_BINARY="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/distributed_pipeline" TRNM_DISTRIBUTED_TEST_OUTPUT="${RUNNER_TEMP:-/tmp}/trnm-distributed-conformance-$$" cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test distributed_roles -- --ignored --test-threads=1
    python3 scripts/run_public_v3_service_campaign.py --out "${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/public-v3-service"
    python3 scripts/test_llm_runtime_pilot.py
    python3 scripts/test_llm_parent_material.py
    python3 scripts/test_llm_runtime_parent_step.py
    python3 scripts/test_llm_runtime_rss_owner.py
    python3 scripts/test_llm_runtime_exit_observation.py
    python3 scripts/test_llm_runtime_stop.py
    python3 scripts/test_llm_inherited_runtime.py
    python3 scripts/test_llm_neural_read_worker.py
    python3 scripts/test_llm_python_runtime_contract.py
    python3 formal/pon-nakamoto-v1/test_reward_budget_oracle.py
    python3 formal/pon-nakamoto-v1/test_demand_evidence.py -v
    python3 formal/pon-nakamoto-v1/test_upgrade_policy.py -v
    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test no_gain_fees --test funded_service_contract --test native_demand_evidence --test native_task_operation_v2 --test native_active_anchor --all-features -- --test-threads=1
    python3 formal/pon-nakamoto-v1/test_model_attribution.py
    python3 formal/pon-nakamoto-v1/test_model_evolution_oracle.py -v
    python3 formal/pon-nakamoto-v1/test_model_task_windows_oracle.py -v
    python3 formal/pon-nakamoto-v1/test_work_utility.py
    python3 formal/pon-nakamoto-v1/test_shared_cell_operator_v1.py
    python3 scripts/ci/test_shared_material_cost_v2.py
    python3 scripts/ci/test_shared_material_security_v1.py
    python3 scripts/ci/test_shared_material_campaign_v2.py
    python3 formal/pon-nakamoto-v1/test_public_evaluation_lifecycle.py
    python3 formal/pon-nakamoto-v1/test_llm_adapter_contract.py
    python3 formal/pon-nakamoto-v1/test_model_acceptance.py
    python3 formal/pon-nakamoto-v1/test_model_window_history.py -v
    python3 formal/pon-nakamoto-v1/test_native_evaluation_quorum_oracle.py -v
    python3 formal/pon-nakamoto-v1/native_evaluation_quorum_oracle.py
    "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuous_pipeline" "${RUNNER_TEMP:-/tmp}/trnm-pipeline-smoke-$$" 2 4 0 growth protected
    python3 formal/pon-nakamoto-v1/test_evaluation_round.py
    python3 formal/pon-nakamoto-v1/test_evaluation.py
    python3 formal/pon-nakamoto-v1/test_evaluation_bundle.py
    python3 formal/pon-nakamoto-v1/test_artifacts.py
    python3 formal/pon-nakamoto-v1/test_inference_receipt.py
    python3 formal/pon-nakamoto-v1/test_bounded_process.py
    python3 formal/pon-nakamoto-v1/test_kernel_process.py
    python3 formal/pon-nakamoto-v1/test_client_confirmation.py
    python3 formal/pon-nakamoto-v1/test_native_session.py
    python3 formal/pon-nakamoto-v1/test_work_precheck.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_SESSION="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute_session" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_client_confirmation.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_SESSION="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute_session" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_contracts.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_SESSION="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute_session" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_invariants.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_EXECUTOR="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_client_confirmation.py
    python3 formal/pon-nakamoto-v1/test_model_contract.py
    python3 formal/pon-nakamoto-v1/test_useful_cell_numeric_v1.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_relation_v1.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_execution_v2.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_relation_v2.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_relation_v2_adversarial.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_source_guard_v2.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_multimodal_execution_v3.py -v
    python3 formal/pon-nakamoto-v1/test_useful_cell_multimodal_relation_v3.py -v
    python3 formal/pon-nakamoto-v1/test_lifecycle_cost_v1.py -v
    python3 formal/pon-nakamoto-v1/test_cell_lottery_cost_audit_v1.py -v
    python3 formal/pon-nakamoto-v1/test_service_work_settlement_v1.py -v
    python3 formal/pon-nakamoto-v1/test_work_backend.py
    python3 formal/pon-nakamoto-v1/test_strict_signature.py
    TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_native_execution.py
    TRNM_NATIVE_EXECUTOR="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_contracts.py
    TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
    TRNM_NATIVE_MODE=release python3 scripts/ci/test_pon_accepted_block.py
    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --bin trnm-cell
    trnm_cell_handoff_binary="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/trnm-cell")"
    test -x "$trnm_cell_handoff_binary"
    TRNM_CELL_BIN="$trnm_cell_handoff_binary" python3 scripts/ci/test_llm_cell_host_handoff.py -v
'''


PQ_RELEASE_WORKFLOW = '.github/workflows/pon-pq-system-continuation.yml'
PQ_RELEASE_MANIFEST = 'config/pon/pq-release-authority-required-tests-v2.json'
PQ_RELEASE_SCOPE = 'release-authority-initial-root-quorum-and-cch1-content-binding-unix-only'
# These are non-wire review pins for the complete, ordered names in each group.
# The original 37, initial-root 6 and quorum 9 remain unchanged; additions require
# an explicit manifest, registry, execution and contract review together.
PQ_RELEASE_GROUPS = {
    'original_release': (37, '41cdd3c0853db168ed869b10ce7579a48fde01d5053b08b7c658d315adbd0cc1'),
    'initial_root_material': (6, 'fc24ff07491d3a6a7fe8712e60ea148796e545ac624e3b3612699c6bc96289bb'),
    'quorum_preflight': (9, '1918b83edb3d238de38bdeac97a0ebc5a313c06a08c11abafcbcc66d233c83d5'),
    'cch1_content_binding': (3, '65079b3c8b33bc2df5850645bcb4c50d551b6050131c208d7601d1fdde9cc2aa'),
}
PQ_ROOT_HARNESS_FILES = (
    'formal/pon-nakamoto-v1/pq_root_quorum_research.py',
    'formal/pon-nakamoto-v1/test_pq_root_quorum_research.py',
)
PQ_ROOT_HARNESS_NAMES_SHA256 = '17ed290cc8ad7b988f012f4cd9119c4197ff8ac3d82c1f655525eb09ae27cac5'
PQ_RELEASE_JOB_HEADER = r'''    name: ML-DSA independent C implementation (${{ matrix.runner }}, ${{ matrix.source }})
    strategy:
      fail-fast: false
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
        source: [head, prospective-merge]
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 25
    defaults:
      run:
        working-directory: chain
    env:
      CARGO_BUILD_JOBS: "2"
      CARGO_INCREMENTAL: "0"
      PYTHONDONTWRITEBYTECODE: "1"
      SOURCE_KIND: ${{ matrix.source }}
      EXPECTED_HEAD: ${{ github.event.pull_request.head.sha }}
      EXPECTED_BASE: ${{ github.event.pull_request.base.sha }}
      EXPECTED_TESTED: ${{ matrix.source == 'head' && github.event.pull_request.head.sha || github.sha }}
    steps:
'''
PQ_RELEASE_AUTHORITY_STEP = r'''      - name: Require all release authority and CCH1 controls from the complete Unix registry
        shell: bash
        run: |
          set -euo pipefail
          out="$RUNNER_TEMP/mldsa-interoperability"
          test -d "$out"
          export CARGO_TARGET_DIR="$RUNNER_TEMP/mldsa-rust-target"
          source_args=(--kind "$SOURCE_KIND" --candidate "$EXPECTED_HEAD" --tested "$EXPECTED_TESTED")
          if test "$SOURCE_KIND" = prospective-merge; then
            source_args+=(--base "$EXPECTED_BASE")
          fi
          python3 scripts/ci/record_pq_native_command.py "${source_args[@]}" --label initial-root-release-registry --output "$out" -- \
            cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-release-bundle --lib -- --list
          python3 - config/pon/pq-release-authority-required-tests-v2.json "$out" <<'PY'
          import json
          import re
          import sys
          from pathlib import Path

          manifest = json.loads(Path(sys.argv[1]).read_text())
          counts = {"original_release": 37, "initial_root_material": 6,
                    "quorum_preflight": 9, "cch1_content_binding": 3, "complete_release": 55}
          if (not isinstance(manifest, dict)
                  or manifest.get("schema") != "trnm-pq-release-authority-required-tests-v2"
                  or manifest.get("package") != "trnm-release-bundle"
                  or manifest.get("harness") != "lib"
                  or manifest.get("platform_scope") != "unix"
                  or manifest.get("scope") != "release-authority-initial-root-quorum-and-cch1-content-binding-unix-only"
                  or not isinstance(manifest.get("expected_controls"), dict)
                  or manifest["expected_controls"] != counts
                  or any(type(value) is not int for value in manifest["expected_controls"].values())
                  or any(manifest.get(key) is not False for key in (
                      "authorization_results_cached", "signature_results_cached", "performance_qualified",
                      "production_activation", "consensus_authority", "whole_chain_quantum_security_qualified"))):
              raise SystemExit("release-authority required-control manifest invalid")
          sets = {}
          for key, count in counts.items():
              names = manifest.get(key + "_tests")
              if (not isinstance(names, list) or len(names) != count
                      or any(not isinstance(name, str) or not re.fullmatch(
                          r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*", name) for name in names)
                      or len(set(names)) != count):
                  raise SystemExit("release-authority required-control names invalid")
              sets[key] = set(names)
          groups = ("original_release", "initial_root_material", "quorum_preflight", "cch1_content_binding")
          if (any(sets[left] & sets[right] for index, left in enumerate(groups)
                  for right in groups[index + 1:])
                  or sets["complete_release"] != set().union(*(sets[group] for group in groups))):
              raise SystemExit("release-authority required-control partition invalid")
          root = Path(sys.argv[2])
          log = (root / "initial-root-release-registry.log").read_text()
          names = re.findall(r"^([A-Za-z0-9_:]+): test$", log, re.M)
          summaries = re.findall(r"^([0-9]+) tests, ([0-9]+) benchmarks$", log, re.M)
          if (len(names) != 55 or len(set(names)) != 55 or set(names) != sets["complete_release"]
                  or summaries != [("55", "0")]):
              raise SystemExit("release-authority actual binary registry differs from the complete required Unix 55")
          prefixes = {"original_release": "original-release", "initial_root_material": "initial-root",
                      "quorum_preflight": "quorum-preflight", "cch1_content_binding": "cch1-content-binding"}
          (root / "release-authority-required.tsv").write_text("".join(
              f"{prefixes[group]}-{index:02d}\t{name}\n"
              for group in groups for index, name in enumerate(manifest[group + "_tests"])))
          print(json.dumps({"scope": "registry-presence-only", "required_controls": counts,
                            "production_activation": False}, sort_keys=True))
          PY
          failed=0
          while IFS=$'\t' read -r label selector; do
            if ! python3 scripts/ci/record_pq_native_command.py "${source_args[@]}" --label "$label" --output "$out" -- \
              cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-release-bundle --lib "$selector" -- --exact --show-output --test-threads=1; then
              failed=1
            elif ! python3 scripts/ci/check_required_native_test.py "$out/$label.log" --test "$selector" > "$out/$label-execution.json"; then
              failed=1
            fi
          done < "$out/release-authority-required.tsv"
          test "$failed" = 0
'''
PQ_ROOT_HARNESS_STEP = r'''      - name: Run root-quorum codec and policy test doubles without native crypto claims
        shell: bash
        run: |
          set -euo pipefail
          out="$RUNNER_TEMP/mldsa-interoperability"
          test -d "$out"
          source_args=(--kind "$SOURCE_KIND" --candidate "$EXPECTED_HEAD" --tested "$EXPECTED_TESTED")
          if test "$SOURCE_KIND" = prospective-merge; then
            source_args+=(--base "$EXPECTED_BASE")
          fi
          python3 scripts/ci/record_pq_native_command.py "${source_args[@]}" --label root-quorum-harness --output "$out" -- \
            python3 -B formal/pon-nakamoto-v1/test_pq_root_quorum_research.py -v
          python3 - "$out/root-quorum-harness.log" > "$out/root-quorum-harness-execution.json" <<'PY'
          import hashlib
          import json
          import re
          import sys
          from pathlib import Path

          text = Path(sys.argv[1]).read_text()
          rows = re.findall(r"^(test_[A-Za-z0-9_]+) \(__main__\.RootQuorumResearchTests\.([A-Za-z0-9_]+)\) \.\.\. (.*)$", text, re.M)
          names = [row[0] for row in rows]
          digest = hashlib.sha256(("\n".join(sorted(names)) + "\n").encode()).hexdigest()
          summaries = re.findall(r"^Ran ([0-9]+) tests? in [0-9]+(?:\.[0-9]+)?s$", text, re.M)
          outcomes = re.findall(r"^(?:OK(?: \(.*\))?|FAILED(?: \(.*\))?)$", text, re.M)
          if (len(rows) != 18 or len(set(names)) != 18
                  or any(name != method or outcome != "ok" for name, method, outcome in rows)
                  or digest != "17ed290cc8ad7b988f012f4cd9119c4197ff8ac3d82c1f655525eb09ae27cac5"
                  or summaries != ["18"] or outcomes != ["OK"]):
              raise SystemExit("root-quorum harness requires all 18 exact codec/policy test doubles")
          print(json.dumps({"result": "PASS", "executed_tests": 18,
                            "scope": "python-codec-policy-test-doubles-only",
                            "native_crypto_observed": False, "production_activation": False}, sort_keys=True))
          PY
'''
PQ_RELEASE_REGRESSION_COMMAND = '          python3 scripts/ci/record_pq_native_command.py "${source_args[@]}" --label recovery-release-components --output "$out" -- \\\n            cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-checkpoint-store -p trnm-release-bundle --all-targets --no-fail-fast -- --test-threads=1\n'


# Required post-win controls retain one literal executable lane and one actual
# saved-receipt verifier step. These source guards do not qualify a proof.
REPOSITORY_TRUTH_BLOCK = r'''    bash scripts/project-preflight.sh --audit
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_envelope_contract.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_normalized_search_cost.py' -v
    python3 scripts/ci/test_project_boundary.py
    # A passing HOLD check does not certify whole-chain PQ or PQ-128.
    python3 scripts/ci/test_pq_lifetime_budget.py
    python3 scripts/ci/pq_lifetime_budget.py
    python3 scripts/ci/test_pq_authority_effect_register.py
    python3 scripts/ci/pq_authority_effect_register.py
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_root_recovery_policy_v1.py' -v
    python3 scripts/ci/test_pq_chain_claim_guard.py
    # Current selected-source mapping retains the historical V1 refusal and all HOLD flags.
    python3 scripts/ci/test_w1_qrom_current_implementation_audit.py
    python3 scripts/w1_qrom_current_implementation_audit.py
    python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v
    python3 scripts/ci/pq_authority_surface_scan.py --summary-only
    python3 -m unittest discover -s scripts/ci -p 'test_pq_external_rollback_oracle.py' -v
    python3 -m unittest discover -s scripts/ci -p 'test_pq_quantum_daa_scenarios.py' -v
    # Public-input framing only: no seed proof or signature qualification.
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_seed_recovery_v1.py' -v

    # Conditional resource/event models retain unknown W1 hardware and protocol gates.
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_work_scale_contract.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_probability_contract.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_feasibility.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential_independent.py' -v
    python3 formal/pon-nakamoto-v1/fixed_probability_contract.py
    python3 formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py --check
    python3 formal/pon-nakamoto-v1/stateful_tail.py
    python3 formal/pon-nakamoto-v1/residual_grover.py
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_fork_witness.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_native_execution_certificate.py' -v
    python3 formal/pon-nakamoto-v1/mandatory_units_tests.py ContextContractTests QueryCertificateTests -v
    python3 formal/pon-nakamoto-v1/certificate_observability_tests.py -v
    python3 formal/pon-nakamoto-v1/lifecycle_query_tests.py -v
    python3 formal/pon-nakamoto-v1/finite_joint_state_tests.py -v
    python3 formal/pon-nakamoto-v1/test_joint_consensus_boundaries.py -v
    python3 formal/pon-nakamoto-v1/certificate_event_coverage_tests.py -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_oracle_resources.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_network_sim.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_candidate_check_clock.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_adversarial_search.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_resource_clock.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_quantum_oracle.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_marked_domain.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_quantum_restricted_oracle.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fast_daa_reference_component.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_parallel_variable_ohie.py' -v
    # Finite ordering and report consistency do not qualify a successor protocol.
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_ghostdag_order_reference.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1/experiments -p 'test_architecture_compare.py' -v
    python3 scripts/ci/pq_chain_claim_guard.py
    python3 scripts/ci/check_repository.py
    python3 scripts/refresh_distributed_source_inventory.py --check
    python3 scripts/ci/test_repository.py
    python3 scripts/ci/test_invariants_registry.py
    python3 scripts/ci/test_responsibility_evidence.py
    python3 scripts/ci/test_applicability.py
    python3 scripts/ci/test_ci_contract.py
    python3 scripts/ci/test_ci_execution.py
    python3 scripts/ci/test_capture_chain_hepta_identity.py
    python3 scripts/ci/test_chain_hepta_qualification.py
    python3 scripts/ci/test_chain_hepta_command_binding.py
    python3 scripts/test_cell_learning_business_economics.py
    python3 scripts/test_cell_learning_business_join.py
    python3 scripts/ci/test_pon_daa_head_binding.py
    python3 -B scripts/ci/test_llm_hosted_once.py
    "${TRNM_RUNTIME_RELEASE_PYTHON:-python3}" scripts/test_llm_runtime_release.py
    python3 scripts/ci/test_replay_pinned_native.py
    python3 scripts/ci/test_cross_arch_cost.py
    python3 scripts/ci/test_zero_locality_cost.py
    python3 scripts/ci/test_zero_paired_cost.py
    python3 scripts/ci/test_one_zero_locality_cost.py
    python3 scripts/ci/test_maintenance_cost.py
    python3 scripts/ci/test_work_rejection_report.py
    python3 scripts/ci/test_six_workpackage_native_rosters.py
    python3 scripts/ci/test_w1_full_v2_disposition.py
    # Historical clocks and finite screening do not qualify a proof for block admission.
    python3 scripts/ci/test_pon_proof_latency.py
    python3 scripts/ci/test_w1_proof_latency_readback.py
    # Real signal/deadline controls and provider contracts do not generate a proof.
    (
      w1_contract_out="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/w1-postwin-contracts"
      test ! -e "$w1_contract_out"
      test ! -L "$w1_contract_out"
      mkdir -p "$(dirname "$w1_contract_out")"
      mkdir "$w1_contract_out"
      w1_contract_tmp="$(mktemp -d /dev/shm/trnm-w1-contract-XXXXXXXX)"
      trap 'rm -rf -- "$w1_contract_tmp"' EXIT
      export TMPDIR="$w1_contract_tmp"
      export PYTHONDONTWRITEBYTECODE=1
      python3 -m unittest discover -s scripts/ci -p test_w1_cancellation_handoff.py -v 2>&1 | tee "$w1_contract_out/cancellation-handoff.log"
      python3 -m unittest discover -s scripts/ci -p test_w1_coordinator_contract.py -v 2>&1 | tee "$w1_contract_out/coordinator-contract.log"
      python3 -m unittest discover -s scripts -p test_kaggle_generation_contract_v2.py -v 2>&1 | tee "$w1_contract_out/provider-contract.log"
      python3 -m unittest discover -s scripts -p test_w1_generation_target_v2.py -v 2>&1 | tee "$w1_contract_out/generation-target.log"
      python3 -m unittest discover -s scripts -p test_w1_owner_cancellation_v1.py -v 2>&1 | tee "$w1_contract_out/owner-cancellation.log"
      python3 -m unittest discover -s scripts/ci -p test_w1_kaggle_source_builder.py -v 2>&1 | tee "$w1_contract_out/source-builder.log"
      python3 -m unittest discover -s scripts -p test_w1_owned_generation_runtime_v2.py -v 2>&1 | tee "$w1_contract_out/owned-runtime-reader.log"
      python3 -m unittest discover -s scripts/ci -p test_w1_kaggle_worker_contract.py -v 2>&1 | tee "$w1_contract_out/kaggle-worker-contract.log"
      python3 -m unittest discover -s scripts/ci -p test_w1_postwin_identity.py -v 2>&1 | tee "$w1_contract_out/winner-identity.log"
      python3 -m unittest discover -s scripts/ci -p test_w1_deployment_evidence_binding.py -v 2>&1 | tee "$w1_contract_out/deployment-evidence-binding.log"
      python3 -m unittest discover -s scripts/ci -p test_w1_deployment_comparison_audit.py -v 2>&1 | tee "$w1_contract_out/deployment-comparison-audit.log"
      python3 scripts/test_w1_owned_process_collector_v1.py -v 2>&1 | tee "$w1_contract_out/owned-process-collector.log"
      python3 - "$w1_contract_out" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
expected = (("cancellation-handoff", 22), ("coordinator-contract", 20),
            ("provider-contract", 11), ("generation-target", 13), ("owner-cancellation", 8),
            ("source-builder", 8),
            ("owned-runtime-reader", 7), ("kaggle-worker-contract", 12), ("winner-identity", 4),
            ("deployment-evidence-binding", 12), ("deployment-comparison-audit", 20),
            ("owned-process-collector", 14))
for name, count in expected:
    text = (root / (name + ".log")).read_text()
    if (re.findall(r"^Ran ([0-9]+) tests in ", text, re.M) != [str(count)]
            or not re.search(r"^OK$", text, re.M) or "skipped=" in text):
        raise SystemExit(f"{name}: all {count} controls must execute without skips")
PY
    )
    python3 scripts/ci/test_pon_w1_preparation_strategy_reader_v4.py
    python3 scripts/ci/test_pon_w1_rank_batch_reader_v5.py
    python3 scripts/ci/test_run_w1_rank_batch_v5.py
    python3 scripts/ci/test_run_legacy_reorg_root_abba.py
    # These in-memory counterexamples use unchanged retained inputs, not a new hardware observation.
    python3 scripts/ci/test_pon_w1_budget_readers.py --raw-dir evidence/pon-upgrade-implementation-20261018/native-rounds/chain-p0-native-54
    python3 scripts/ci/test_pon_public_v3_phase_read.py
    python3 scripts/ci/test_pon_public_v3_policy_read.py
    python3 scripts/ci/test_pon_v3_cookie_cpu_study.py
    python3 scripts/ci/test_run_pon_w1_native_campaign.py
    python3 scripts/ci/test_read_validated_business_goodput.py
    python3 scripts/ci/test_pon_w1_cost_matrix_reader.py
    python3 scripts/ci/test_pon_w1_reused_cost_reader_v3.py
    python3 scripts/ci/test_run_w1_reused_cost_v3.py
    python3 scripts/ci/test_w1_lifecycle_cost_v4.py
    python3 scripts/ci/test_llm_cell_handoff_deadline.py
    python3 scripts/ci/test_read_original_native_campaign.py \
      --artifact-dir evidence/pon-upgrade-implementation-20261018/native-rounds/chain-pr327-original-campaign-39694587963 \
      --expected-manifest-sha256 12406cc156e57c130fa14af2b50b386031ec3640ce7f0234ed5bc9f0a700aac3 \
      --expected-head 9e705ccf75b7318dcc4bda4815956f58beb10e72 \
      --expected-tree 521ae87a28060d545979069b189eebbc74a71fd8 --retained-subset
    python3 scripts/ci/test_account_archive_conformance.py
    python3 scripts/ci/test_run_account_execution_conformance.py
    python3 scripts/ci/report_current_implementation.py --check
    python3 scripts/ci/test_work_cost_report.py
    python3 scripts/test_qualification_runtime.py
'''

# Independent literal for the existing external lane. A command inside a false
# branch or an errexit-suppressing shell condition is not an executed control.
EXTERNAL_EVIDENCE_CONTRACT_BLOCK = '''    python3 scripts/ci/prepare_evidence_sources.py
    python3 scripts/ci/test_evidence_sources.py
    python3 scripts/ci/check_repository.py
    python3 scripts/ci/test_repository.py EvidenceBoundaryTests
    python3 scripts/ci/check_pon_evidence.py
    python3 scripts/ci/test_pon_evidence.py
    python3 scripts/ci/check_invariant_evidence.py --historical
    python3 scripts/ci/test_invariant_evidence.py
    python3 scripts/ci/check_completion_evidence.py --historical
    python3 scripts/ci/test_completion_evidence.py
    python3 scripts/ci/check_evaluation_bundle_evidence.py --historical
    python3 scripts/ci/check_client_confirmation_evidence.py --historical
    python3 scripts/ci/check_client_confirmation_evidence.py --historical --evidence evidence/pon-native-session-v1
    python3 scripts/ci/check_client_confirmation_evidence.py --historical --evidence evidence/pon-native-node-v1
    python3 scripts/ci/check_client_confirmation_evidence.py --historical --evidence evidence/pon-closed-round-v1
    python3 scripts/ci/check_public_readiness_evidence.py --historical --evidence evidence/pon-public-readiness-v1
    python3 scripts/ci/test_public_readiness_evidence.py
    python3 scripts/ci/check_native_node_supplements.py --historical
    python3 scripts/ci/test_native_node_supplements.py
    python3 scripts/ci/test_native_session_evidence.py
    python3 scripts/ci/test_client_confirmation_evidence.py
    python3 scripts/ci/test_evaluation_bundle_evidence.py
    python3 scripts/ci/report_module_evidence.py --format markdown
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-contract-authority-v1/work-cost --historical
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-native-session-v1/work-cost --historical
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-native-node-v1/work-cost --historical
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-closed-round-v1/work-cost --historical
    python3 scripts/ci/check_four_priority_evidence.py
    python3 scripts/ci/test_four_priority_evidence.py
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-four-priority-audit-v1/work-cost --historical
'''


W1_POSTWIN_WORKFLOW_PREFIX = r'''name: PoN W1 transparent candidate observations
on:
  pull_request:
    paths:
      - formal/pon-nakamoto-v1/w1_hardened_verifier/**
      - formal/pon-nakamoto-v1/w1_v2_verifier/**
      - formal/pon-nakamoto-v1/w1_native_cost/**
      - formal/pon-nakamoto-v1/w1_zkvm/**
      - formal/pon-nakamoto-v1/experiments/w1_full_staged_run.py
      - formal/pon-nakamoto-v1/experiments/w1_stage_measure.py
      - formal/pon-nakamoto-v1/experiments/w1_local_payload.py
      - trillionnium/**
      - scripts/w1_transparent_compare.py
      - scripts/w1_profile_source_map.py
      - scripts/w1_security_budget.py
      - scripts/w1_v2_receipt_controls.py
      - scripts/run_w1_receiver.py
      - scripts/run_w1_postwin_proof.py
      - scripts/run_w1_deployment_comparison.py
      - scripts/audit_w1_deployment_comparison.py
      - scripts/build_w1_kaggle_source.py
      - scripts/kaggle_generation_contract_v2.py
      - scripts/test_kaggle_generation_contract_v2.py
      - scripts/w1_generation_target_v2.py
      - scripts/test_w1_generation_target_v2.py
      - scripts/w1_owner_cancellation_v1.py
      - scripts/test_w1_owner_cancellation_v1.py
      - scripts/w1_owned_generation_runtime_v2.py
      - scripts/test_w1_owned_generation_runtime_v2.py
      - scripts/w1_owned_process_collector_v1.py
      - scripts/test_w1_owned_process_collector_v1.py
      - evidence/pon-w1-full-v2-20261105/**
      - evidence/pon-w1-fresh-runtime-20261107/**
      - evidence/pon-w1-backend-sdk-20261107/**
      - scripts/w1_kaggle_worker_template.py
      - scripts/ci/**
      - scripts/project-preflight.sh
      - evidence/pon-w1-complete-succinct-20261028/**
      - evidence/pon-w1-full-v2-20261105/**
      - evidence/pon-w1-verifier-hardening-20261028/**
      - evidence/pon-w1-transparent-profile-20261104/**
      - evidence/pon-w1-stark-review-20261106/**
      - evidence/pon-w1-source-snapshot-20261106/**
      - evidence/pon-w1-statement-v2-20261105/**
      - evidence/pon-w1-qrom-budget-20261105/**
      - config/**
      - .cargo/**
      - rust-toolchain.toml
      - AGENTS.md
      - PROJECT_ID
      - PROJECT_BOUNDARY.json
      - .github/workflows/pon-w1-transparent-profile.yml
permissions:
  contents: read
concurrency:
  group: pon-w1-transparent-profile-${{ github.event.pull_request.number }}
  # Preserve failed and partial observations when a newer source arrives.
  cancel-in-progress: false
env:
  CI: "true"
  CARGO_INCREMENTAL: "0"
  CARGO_BUILD_JOBS: "2"
  RUST_TEST_THREADS: "1"
  CARGO_TERM_COLOR: never
  PYTHONDONTWRITEBYTECODE: "1"
jobs:
  transparent-profile:
    name: W1 transparent candidate (${{ matrix.source }}, x64)
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    strategy:
      fail-fast: false
      matrix:
        source: [head, prospective-merge]
    env:
      SOURCE_KIND: ${{ matrix.source }}
      EXPECTED_SOURCE: ${{ matrix.source == 'head' && github.event.pull_request.head.sha || github.sha }}
      EXPECTED_HEAD: ${{ github.event.pull_request.head.sha }}
      EXPECTED_BASE: ${{ github.event.pull_request.base.sha }}
    steps:
'''

W1_POSTWIN_CRITICAL_STEPS = {
    "checkout": r'''      - name: Checkout exact candidate without persistent credentials
        id: checkout
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          ref: ${{ env.EXPECTED_SOURCE }}
          fetch-depth: 0
          persist-credentials: false
''',
    "source": r'''      - name: Reserve observations and verify ordered source identity
        id: source
        shell: bash
        run: |
          set -euo pipefail
          w1_profile_out="$RUNNER_TEMP/pon-w1-transparent-profile-$SOURCE_KIND-x64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
          mkdir "$w1_profile_out"
          mkdir "$w1_profile_out/bin"
          printf 'W1_PROFILE_OUT=%s\n' "$w1_profile_out" >> "$GITHUB_ENV"
          printf 'CARGO_HOME=%s/cargo-w1-transparent-profile-%s-%s-%s\n' "$RUNNER_TEMP" "$SOURCE_KIND" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" >> "$GITHUB_ENV"
          printf 'CARGO_TARGET_DIR=%s/target-w1-transparent-profile-%s-%s-%s\n' "$RUNNER_TEMP" "$SOURCE_KIND" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" >> "$GITHUB_ENV"
          printf 'Continuous candidate checks and saved-proof observations only. No new proof, end-to-end benefit, quantum soundness, production or consensus-admission qualification is established.\n' > "$w1_profile_out/SCOPE.txt"
          args=(--kind "$SOURCE_KIND" --expected-head "$EXPECTED_HEAD")
          if test "$SOURCE_KIND" = prospective-merge; then
            args+=(--expected-base "$EXPECTED_BASE" --expected-merge "$EXPECTED_SOURCE")
          fi
          python3 scripts/ci/verify_ci_source.py "${args[@]}" --output "$w1_profile_out/source-before.json" 2>&1 | tee "$w1_profile_out/source-before.log"
          bash scripts/project-preflight.sh --audit 2>&1 | tee "$w1_profile_out/preflight.log"
''',
    "toolchain": r'''      - name: Install pinned compiler and retain tool identities
        id: toolchain
        shell: bash
        run: |
          set -euo pipefail
          rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy 2>&1 | tee "$W1_PROFILE_OUT/toolchain-install.log"
          rustc +1.95.0 -Vv > "$W1_PROFILE_OUT/rustc-version.txt"
          cargo +1.95.0 -Vv > "$W1_PROFILE_OUT/cargo-version.txt"
          python3 --version > "$W1_PROFILE_OUT/python-version.txt"
''',
    "mapper_tests": r'''      - name: Execute all 15 offline source-map controls
        if: always() && steps.source.outcome == 'success'
        id: mapper_tests
        shell: bash
        run: |
          set -euo pipefail
          python3 -m unittest discover -s scripts/ci -p test_w1_profile_source_map.py -v 2>&1 | tee "$W1_PROFILE_OUT/mapper-tests.log"
          python3 - "$W1_PROFILE_OUT/mapper-tests.log" <<'PY'
          from pathlib import Path
          import re, sys
          text = Path(sys.argv[1]).read_text()
          expected = {
              'test_archive_and_selected_members_match_locked_checksum',
              'test_archive_replacement_does_not_change_the_inspected_snapshot',
              'test_archive_replacement_with_matching_changed_sources_is_refused',
              'test_duplicate_and_missing_locked_packages_are_refused',
              'test_duplicate_archive_member_is_refused',
              'test_existing_output_is_never_overwritten',
              'test_json_snapshot_keeps_the_digest_of_the_parsed_bytes',
              'test_json_snapshot_preserves_duplicate_key_refusal',
              'test_lock_snapshot_keeps_the_digest_of_the_parsed_bytes',
              'test_locked_archive_checksum_drift_is_refused',
              'test_modified_extracted_source_is_refused',
              'test_oversized_selected_archive_member_is_refused',
              'test_provenance_is_parsed_from_the_hashed_source_snapshot',
              'test_source_size_and_digest_describe_the_same_read',
              'test_stark_value_or_declaration_drift_is_refused',
          }
          rows = re.findall(r'^(test_\S+) \(([^)]+)\) \.\.\. (.*)$', text, re.M)
          required = sorted((name, f'test_w1_profile_source_map.SourceMapTests.{name}', 'ok')
                            for name in expected)
          if (sorted(rows) != required
                  or re.findall(r'^Ran ([0-9]+) tests in ', text, re.M) != ['15']
                  or re.findall(r'^OK(?: \(.*\))?$', text, re.M) != ['OK']):
              raise SystemExit('all 15 named source-map controls must execute exactly once without skips')
          PY
''',
    "v2_gate_tests": r'''      - name: Execute all 23 saved-v2 report consistency controls
        if: always() && steps.source.outcome == 'success'
        id: v2_gate_tests
        shell: bash
        run: |
          set -euo pipefail
          python3 -m unittest discover -s scripts/ci -p test_w1_v2_controls_gate.py -v 2>&1 | tee "$W1_PROFILE_OUT/v2-gate-tests.log"
          python3 - "$W1_PROFILE_OUT/v2-gate-tests.log" <<'PY'
          from pathlib import Path
          import re, sys
          text = Path(sys.argv[1]).read_text()
          expected = {
              'test_budget_and_qualification_cannot_be_widened',
              'test_case_command_must_use_pinned_verifier',
              'test_case_command_must_use_planned_inputs',
              'test_case_result_must_match_summary',
              'test_incomplete_session_observation_is_rejected',
              'test_integer_exit_codes_cannot_be_booleans',
              'test_mutation_identity_must_match_planned_bytes',
              'test_negative_process_acceptance_is_rejected',
              'test_nested_timeout_is_rejected',
              'test_original_control_order_and_count_are_required',
              'test_output_hashes_must_match_saved_logs',
              'test_positive_process_rejection_is_rejected',
              'test_positive_stdout_must_match_summary',
              'test_process_pid_must_belong_to_observed_groups',
              'test_process_scan_errors_are_rejected',
              'test_real_saved_controls_pass',
              'test_rejection_layer_must_match_saved_stderr',
              'test_required_rejection_text_must_be_present',
              'test_retained_process_must_match_summary',
              'test_saved_inputs_must_match_planned_bytes',
              'test_truncated_output_scans_are_rejected',
              'test_unsettled_owned_groups_are_rejected',
              'test_verifier_hash_must_match_pinned_identity',
          }
          rows = re.findall(r'^(test_\S+) \(([^)]+)\) \.\.\. (.*)$', text, re.M)
          required = sorted((name, f'test_w1_v2_controls_gate.V2ControlsGateTests.{name}', 'ok')
                            for name in expected)
          if (sorted(rows) != required
                  or re.findall(r'^Ran ([0-9]+) tests in ', text, re.M) != ['23']
                  or re.findall(r'^OK(?: \(.*\))?$', text, re.M) != ['OK']):
              raise SystemExit('all 23 named v2 report controls must execute exactly once without skips')
          PY
          python3 -m unittest discover -s scripts/ci -p test_w1_v2_current_stage_gate.py -v 2>&1 | tee "$W1_PROFILE_OUT/v3-gate-tests.log"
          python3 - "$W1_PROFILE_OUT/v3-gate-tests.log" <<'PY'
          from pathlib import Path
          import re, sys
          text = Path(sys.argv[1]).read_text()
          expected = {
              'test_current_cli_selects_current_schema_without_a_downgrade_option',
              'test_current_contract_accepts_actual_clean_expected_rejection',
              'test_current_contract_accepts_actual_clean_process_observation',
              'test_current_contract_refuses_deadline_exhaustion',
              'test_current_contract_refuses_legacy_and_unknown_observations',
              'test_current_contract_refuses_snapshot_cancellation',
              'test_current_contract_requires_every_new_snapshot_field',
              'test_current_contract_retains_unqualified_resource_and_proof_scope',
              'test_current_snapshot_fields_cannot_coerce_types',
              'test_version_selector_is_explicit_and_unknown_versions_are_refused',
          }
          rows = re.findall(r'^(test_\S+) \(([^)]+)\) \.\.\. (.*)$', text, re.M)
          required = sorted((name, f'test_w1_v2_current_stage_gate.CurrentStageV3ControlsGateTests.{name}', 'ok')
                            for name in expected)
          if (sorted(rows) != required
                  or re.findall(r'^Ran ([0-9]+) tests in ', text, re.M) != ['10']
                  or re.findall(r'^OK(?: \(.*\))?$', text, re.M) != ['OK']):
              raise SystemExit('all 10 current stage-v3 controls must execute exactly once without skips')
          PY
''',
    "staged_tests": r'''      - name: Execute staged lifecycle and complete-observation rejection controls
        if: always() && steps.source.outcome == 'success'
        id: staged_tests
        shell: bash
        run: |
          set -euo pipefail
          w1_staged_tmp="$(mktemp -d /dev/shm/trnm-w1-staged-ci-XXXXXXXX)"
          trap 'rm -rf -- "$w1_staged_tmp"' EXIT
          export TMPDIR="$w1_staged_tmp"
          python3 -m unittest discover -s scripts/ci -p test_w1_staged_observer.py -v 2>&1 | tee "$W1_PROFILE_OUT/staged-observer-tests.log"
          python3 - "$W1_PROFILE_OUT/staged-observer-tests.log" <<'PY'
          from pathlib import Path
          import re, sys
          text = Path(sys.argv[1]).read_text()
          counts = re.findall(r'^Ran ([0-9]+) tests in ', text, re.M)
          if counts != ['32'] or not re.search(r'^OK$', text, re.M) or 'skipped=' in text:
              raise SystemExit('all 32 retained staged-observer controls must execute without skips')
          PY
''',
    "verifier_v2": r'''      - name: Verify and build the independent v2 verifier without a guest build
        if: always() && steps.source.outcome == 'success' && steps.toolchain.outcome == 'success'
        id: verifier_v2
        shell: bash
        run: |
          set -euo pipefail
          w1_manifest=formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml
          cargo +1.95.0 metadata --locked --manifest-path "$w1_manifest" --format-version 1 > "$W1_PROFILE_OUT/v2-cargo-graph.json" 2> "$W1_PROFILE_OUT/v2-metadata.stderr.log"
          python3 - "$W1_PROFILE_OUT/v2-cargo-graph.json" <<'PY'
          from pathlib import Path
          import json, sys
          graph = json.loads(Path(sys.argv[1]).read_text())
          packages = {package['name'] for package in graph['packages']}
          if packages.intersection({'risc0-build', 'trnm-w1-zk-methods', 'trnm-w1-zk-methods-v2',
                                    'trnm-w1-full-guest', 'trnm-w1-full-guest-v2'}):
              raise SystemExit('independent v2 verifier must not acquire a guest build dependency')
          PY
          cargo +1.95.0 fmt --manifest-path "$w1_manifest" --all -- --check 2>&1 | tee "$W1_PROFILE_OUT/v2-format.log"
          cargo +1.95.0 test --locked --release --manifest-path "$w1_manifest" -- --format=pretty --test-threads=1 2>&1 | tee "$W1_PROFILE_OUT/v2-tests.log"
          python3 - "$W1_PROFILE_OUT/v2-tests.log" <<'PY'
          from pathlib import Path
          import re, sys
          text = Path(sys.argv[1]).read_text()
          expected = {
              'tests::expected_artifacts_are_exact_and_never_derived_from_receipt',
              'tests::historical_full_receipt_cannot_satisfy_v2_statement',
              'tests::saved_full_v2_receipt_verifies_with_independent_artifacts',
          }
          rows = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (\S+)$', text, re.M)
          summaries = re.findall(r'^test result: (.*)$', text, re.M)
          if (len(rows) != 3 or {name for name, _ in rows} != expected
                  or any(outcome != 'ok' for _, outcome in rows)
                  or re.findall(r'^running ([0-9]+) tests$', text, re.M) != ['3']
                  or len(summaries) != 1 or not re.fullmatch(
                      r'ok\. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9]+(?:\.[0-9]+)?s',
                      summaries[0])):
              raise SystemExit('all three named v2 controls, including the actual saved proof, must execute without filtering')
          PY
          cargo +1.95.0 clippy --locked --release --manifest-path "$w1_manifest" --all-targets -- -D warnings 2>&1 | tee "$W1_PROFILE_OUT/v2-clippy.log"
          cargo +1.95.0 build --locked --release --manifest-path "$w1_manifest" 2>&1 | tee "$W1_PROFILE_OUT/v2-build.log"
          cp "$CARGO_TARGET_DIR/release/w1-verify-v2" "$W1_PROFILE_OUT/bin/w1-verify-v2"
          sha256sum "$W1_PROFILE_OUT/bin/w1-verify-v2" > "$W1_PROFILE_OUT/v2-binary.sha256"
''',
    "real_receiver_controls": r'''      - name: Execute eleven actual full-v2 receiver and cancellation controls
        if: always() && steps.source.outcome == 'success' && steps.verifier_v2.outcome == 'success'
        id: real_receiver_controls
        shell: bash
        run: |
          set -euo pipefail
          w1_v2_fixture="$GITHUB_WORKSPACE/evidence/pon-w1-full-v2-20261105"
          w1_v2_verifier="$W1_PROFILE_OUT/bin/w1-verify-v2"
          w1_v2_verifier_sha="$(sha256sum "$w1_v2_verifier")"
          w1_v2_verifier_sha="${w1_v2_verifier_sha%% *}"
          python3 - "$w1_v2_fixture" <<'PY'
          from pathlib import Path
          import hashlib, sys
          root = Path(sys.argv[1])
          expected = {
              "succinct.bin": (257014, "6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee"),
              "input.bin": (49506, "67b74fa2f417c0240d974e5ecea410d2b68d97d6dde667603aeb4d7ce59036cb"),
              "header.bin": (318, "7b96038f228a1eedccf7b29ffc54802aba691be7259e33937846c6bf6126d78f"),
              "expected-artifacts.bin": (64, "802adcdd951cfb4cd7271df22c3bca6af66fee9f40454c74f8b5ff2c98a1b683"),
          }
          for name, (size, digest) in expected.items():
              raw = (root / name).read_bytes()
              if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                  raise SystemExit("historical full-v2 fixture changed: " + name)
          if (root / "input.bin").read_bytes()[:318] != (root / "header.bin").read_bytes():
              raise SystemExit("full-v2 input/header binding changed")
          PY
          python3 scripts/ci/test_w1_receiver_real.py \
            --verifier "$w1_v2_verifier" --verifier-sha256 "$w1_v2_verifier_sha" \
            --receipt "$w1_v2_fixture/succinct.bin" --input "$w1_v2_fixture/input.bin" \
            --header "$w1_v2_fixture/header.bin" --expected-artifacts "$w1_v2_fixture/expected-artifacts.bin" \
            --out "$W1_PROFILE_OUT/real-receiver-controls" 2>&1 | tee "$W1_PROFILE_OUT/real-receiver-controls.log"
          python3 - "$W1_PROFILE_OUT/real-receiver-controls/summary.json" "$w1_v2_verifier_sha" <<'PY'
          from pathlib import Path
          import json, sys
          report = json.loads(Path(sys.argv[1]).read_text())
          counts = {"tests_run": 11, "failures": 0, "errors": 0, "skipped": 0, "fresh_proof_generations": 0}
          if (report.get("schema") != "TRNM-W1-REAL-RECEIVER-CONTROLS1"
                  or any(type(report.get(key)) is not int or report[key] != value for key, value in counts.items())
                  or report.get("result") != "PASS" or report.get("actual_complete_receipt_used") is not True
                  or report.get("verifier_sha256") != sys.argv[2]
                  or report.get("receipt_sha256") != "6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee"):
              raise SystemExit("all eleven actual receiver controls must execute with the declared saved receipt and zero proof generation")
          PY

''',
    "receipt_controls_v2": r'''      - name: Retain all 58 actual saved-v2 receipt controls
        if: always() && steps.source.outcome == 'success' && steps.verifier_v2.outcome == 'success'
        id: receipt_controls_v2
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
          w1_proof_dir="$GITHUB_WORKSPACE/evidence/pon-w1-full-v2-20261105"
          w1_verifier="$W1_PROFILE_OUT/bin/w1-verify-v2"
          RAYON_NUM_THREADS=8 python3 scripts/w1_v2_receipt_controls.py \
            --verifier "$w1_verifier" --receipt "$w1_proof_dir/succinct.bin" \
            --header "$w1_proof_dir/header.bin" --expected-artifacts "$w1_proof_dir/expected-artifacts.bin" \
            --out "$W1_PROFILE_OUT/v2-controls" 2>&1 | tee "$W1_PROFILE_OUT/v2-receipt-controls.log"
          python3 scripts/ci/w1_v2_controls_gate.py "$W1_PROFILE_OUT/v2-controls" "$w1_proof_dir" "$w1_verifier" \
            2>&1 | tee "$W1_PROFILE_OUT/v2-controls-validation.log"
''',
    "source_after": r'''      - name: Verify measured source after execution
        if: always() && steps.source.outcome == 'success'
        id: source_after
        shell: bash
        run: |
          set -euo pipefail
          args=(--kind "$SOURCE_KIND" --expected-head "$EXPECTED_HEAD")
          if test "$SOURCE_KIND" = prospective-merge; then
            args+=(--expected-base "$EXPECTED_BASE" --expected-merge "$EXPECTED_SOURCE")
          fi
          python3 scripts/ci/verify_ci_source.py "${args[@]}" --output "$W1_PROFILE_OUT/source-after.json" 2>&1 | tee "$W1_PROFILE_OUT/source-after.log"
''',
}
W1_POSTWIN_REQUIRED_OUTCOMES_STEP = r'''      - name: Record completed, failed and skipped observations
        if: always()
        shell: bash
        env:
          W1_PROFILE_STEP_RESULTS: ${{ toJSON(steps) }}
        run: |
          set -euo pipefail
          w1_profile_out="$RUNNER_TEMP/pon-w1-transparent-profile-$SOURCE_KIND-x64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
          mkdir -p "$w1_profile_out"
          python3 - "$w1_profile_out/ci-status.json" <<'PY'
          import json, os, sys
          report = {'schema': 'TRNM-W1-TRANSPARENT-CI-OBSERVATION1',
              'source_kind': os.environ['SOURCE_KIND'], 'expected_source': os.environ['EXPECTED_SOURCE'],
              'steps': json.loads(os.environ['W1_PROFILE_STEP_RESULTS']),
              'scope': 'Continuous candidate checks; failed and partial observations are retained.',
              'end_to_end_benefit_established': False, 'quantum_soundness_qualified': False,
              'production_qualified': False, 'consensus_admission': False}
          with open(sys.argv[1], 'x', encoding='utf-8') as stream:
              json.dump(report, stream, indent=2, sort_keys=True)
              stream.write('\n')
          required = ('checkout', 'source', 'toolchain', 'source_controls', 'observer_tests',
                      'mapper_tests', 'v2_gate_tests', 'staged_tests', 'budget_tests', 'native', 'hardened',
                      'verifier_v2', 'real_receiver_controls', 'receipt_controls_v2', 'component_budget', 'source_map',
                      'profile', 'receipt_controls', 'comparison', 'source_after')
          incomplete = [name for name in required if report['steps'].get(name, {}).get('outcome') != 'success']
          if incomplete:
              raise SystemExit('required W1 observations failed or were skipped: ' + ', '.join(incomplete))
          PY
'''
W1_POSTWIN_REQUIRED_STEP_IDS = ('checkout', 'source', 'toolchain', 'source_controls', 'observer_tests', 'mapper_tests', 'v2_gate_tests', 'staged_tests', 'budget_tests', 'native', 'hardened', 'verifier_v2', 'real_receiver_controls', 'receipt_controls_v2', 'component_budget', 'source_map', 'profile', 'receipt_controls', 'comparison', 'source_after')
W1_POSTWIN_REQUIRED_TEST_FILES = (
    "scripts/ci/test_w1_cancellation_handoff.py",
    "scripts/ci/test_w1_coordinator_contract.py",
    "scripts/test_kaggle_generation_contract_v2.py",
    "scripts/test_w1_generation_target_v2.py",
    "scripts/test_w1_owner_cancellation_v1.py",
    "scripts/ci/test_w1_kaggle_source_builder.py",
    "scripts/test_w1_owned_generation_runtime_v2.py",
    "scripts/ci/test_w1_kaggle_worker_contract.py",
    "scripts/ci/test_w1_postwin_identity.py",
    "scripts/ci/test_w1_deployment_evidence_binding.py",
    "scripts/ci/test_w1_deployment_comparison_audit.py",
    "scripts/test_w1_owned_process_collector_v1.py",
)

def check_w1_postwin_workflow(text: str) -> None:
    """Require the real saved-v2 verifier controls after their successful build."""
    require(text.startswith(W1_POSTWIN_WORKFLOW_PREFIX),
            'W1 post-win workflow retains exact triggers, source matrix, permissions and budgets')
    require(text.count('\njobs:\n') == 1
            and re.findall(r'^  ([a-z][a-z0-9-]*):\n', text.split('\njobs:\n')[1], re.M)
                == ['transparent-profile'],
            'W1 post-win controls retain their one transparent-profile job')
    require('continue-on-error' not in text and 'pull_request_target' not in text
            and 'contents: write' not in text and 'self-hosted' not in text,
            'W1 post-win workflow may not soften failures or gain privileges')
    blocks = re.findall(r'(?ms)^      - name: .*?(?=^      - name: |\Z)', text)
    steps = {}
    ordered = []
    for block in blocks:
        ids = re.findall(r'^        id: ([a-z][a-z0-9_]*)$', block, re.M)
        require(len(ids) <= 1, 'W1 post-win step has one identity')
        if ids:
            require(ids[0] not in steps, 'W1 post-win step identity is unique')
            steps[ids[0]] = block
            ordered.append(ids[0])
    for name, expected in W1_POSTWIN_CRITICAL_STEPS.items():
        require(steps.get(name) == expected,
                'W1 post-win ' + name + ' retains its exact executable source/build/control block')
    require(tuple(ordered) == W1_POSTWIN_REQUIRED_STEP_IDS,
            'W1 post-win retains every original stage and both receiver suites in their reviewed order')
    outcomes = [block for block in blocks if block.startswith(
        '      - name: Record completed, failed and skipped observations\n')]
    require(outcomes == [W1_POSTWIN_REQUIRED_OUTCOMES_STEP]
            and text.index(W1_POSTWIN_REQUIRED_OUTCOMES_STEP) > text.index(steps['source_after']),
            'W1 post-win final readback requires all stages, both receiver suites and retained failures')
    for command in ('python3 scripts/ci/test_w1_receiver_real.py',
                    'python3 -m unittest discover -s scripts/ci -p test_w1_staged_observer.py -v',
                    'python3 -m unittest discover -s scripts/ci -p test_w1_profile_source_map.py -v',
                    'python3 -m unittest discover -s scripts/ci -p test_w1_v2_controls_gate.py -v',
                    'python3 scripts/w1_v2_receipt_controls.py',
                    'python3 scripts/ci/w1_v2_controls_gate.py'):
        require(text.count(command) == 1,
                'W1 post-win saved-receipt and retained staged controls execute once')
    for name in W1_POSTWIN_REQUIRED_TEST_FILES:
        require(name.rsplit('/', 1)[1] not in ''.join(blocks),
                'W1 post-win required repository-truth controls cannot be duplicated into an optional workflow')


def code_lines(text: str) -> list[str]:
    """The fixed lane permits whole-line comments, not alternate shell control flow."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]


def check_independent_conformance(script: str, required: set[str]) -> None:
    require(script.startswith('#!/usr/bin/env bash\nset -euo pipefail\n'),
            'lane execution must propagate actual failures')
    pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*)\)\n(.*?)(?=^    ;;$)', script)
    lanes = dict(pairs)
    require(len(pairs) == len(lanes) and set(lanes) == required, 'exact five executable lane selectors')
    pq_commands = code_lines(PQ_MIGRATION_CONFORMANCE_PREFIX)
    require(code_lines(lanes['protocol-contract'])[:len(pq_commands)] == pq_commands
            and all(code_lines(script).count(command) == 1 for command in pq_commands),
            'offline migration and seed relation controls must execute exactly once at the start of protocol-contract with the fixed warning policy')
    parent_material = '    python3 scripts/test_llm_parent_material.py\n'
    parent_step = '    python3 scripts/test_llm_runtime_parent_step.py\n'
    for command in (parent_material, parent_step):
        require(command in lanes['protocol-contract'] and script.count(command) == 1,
                'parent material and parent-step byte checks must execute exactly once in protocol-contract')
    for command in CURRENT_READER_COMMANDS:
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'current cost, policy and cell deadline reader controls must execute exactly once in repository-truth')
    for command in ('python3 scripts/test_cell_learning_business_economics.py',
                    'python3 scripts/test_cell_learning_business_join.py'):
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'learning business readback controls must execute exactly once in repository-truth')
    for command in PROOF_LATENCY_READER_COMMANDS:
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'proof latency controls must execute exactly once in repository-truth')
    for path in W1_POSTWIN_REQUIRED_TEST_FILES:
        name = path.rsplit('/', 1)[1]
        require(sum(line.count(name) for line in code_lines(lanes['repository-truth'])) == 1
                and sum(line.count(name) for line in code_lines(script)) == 1,
                'W1 post-win controls must execute exactly once globally and in repository-truth')
    runtime_pilot = '    python3 scripts/test_llm_runtime_pilot.py\n'
    require(runtime_pilot + parent_material + parent_step + LLM_RUNTIME_TESTS in lanes['protocol-contract']
            and all(code_lines(script).count(command) == 1
                    for command in code_lines(LLM_RUNTIME_TESTS)),
            'runtime owner, exit, inheritance and neural worker controls must retain their straight-line command sequence exactly once after pilot, parent material and parent step in protocol-contract')
    reward_budgets = '    python3 formal/pon-nakamoto-v1/test_reward_budget_oracle.py\n'
    require(reward_budgets in lanes['protocol-contract'] and script.count(reward_budgets) == 1,
            'five-lane reward budget controls must execute exactly once in protocol-contract')
    require(reward_budgets + DEMAND_UPGRADE_CONTROLS in lanes['protocol-contract'] and
            all(script.count(command) == 1 for command in DEMAND_UPGRADE_CONTROLS.splitlines(keepends=True)),
            'demand evidence and continuous upgrade controls must execute exactly once after reward budgets in protocol-contract')
    require(DEMAND_UPGRADE_CONTROLS + NATIVE_DEMAND_CONTRACTS in lanes['protocol-contract']
            and script.count(NATIVE_DEMAND_CONTRACTS) == 1,
            'native demand and funded Task contract controls must execute exactly once after the reference controls')
    require(code_lines(lanes['protocol-contract']).count(GSC2_SYNTHETIC_ORACLE.strip()) == 1
            and code_lines(script).count(GSC2_SYNTHETIC_ORACLE.strip()) == 1,
            'GSC2 synthetic readback counterexamples must execute exactly once in protocol-contract with the current source root')
    continuity = CONTINUITY_BUILD + CONTINUITY_ORIGINAL + CONTINUITY_TRANSITIONS + PAIRED_WORK_ORACLE + ZERO_WORK_ORACLE
    require(continuity in lanes['protocol-contract'] and script.count(CONTINUITY_ORIGINAL) == 1
            and script.count(CONTINUITY_TRANSITIONS) == 1,
            'continuity and paired-work oracles must execute in protocol-contract after their actual release build')
    require(script.count(PAIRED_WORK_ORACLE) == 1,
            'one native paired-work byte comparison must retain its fresh current-lane output')
    require(script.count(ZERO_WORK_ORACLE) == 1,
            'one native zero-work byte comparison must retain its fresh current-lane output after its release build')
    require(code_lines(lanes['protocol-contract']).count(MANDATORY_UNITS_NATIVE.strip()) == 1
            and code_lines(script).count(MANDATORY_UNITS_NATIVE.strip()) == 1,
            'complete MU1 controls require both current native W1 binaries exactly once in protocol-contract')
    for block, build, label in ((WORK_LIFECYCLE_NATIVE, CONTINUITY_BUILD, 'W1/PQ lifecycle'),
                                (NATIVE_OWNER_SCORE_BRIDGE, NODE_EXAMPLE_BUILD, 'native owner score bridge'),
                                (LIFECYCLE_QUERY_NATIVE, CONTINUITY_BUILD, 'lifecycle query observation'),
                                (NATIVE_OWNER_JOURNAL, NODE_EXAMPLE_BUILD, 'durable native owner and composition'),
                                (NATIVE_RISK_LEDGER, NODE_EXAMPLE_BUILD, 'durable native confirmation risk bank')):
        require(block in lanes['protocol-contract']
                and all(code_lines(script).count(line) == 1 for line in code_lines(block))
                and build in lanes['protocol-contract']
                and lanes['protocol-contract'].index(build) < lanes['protocol-contract'].index(block),
                label + ' must execute current native binaries once after their build and retain fresh observations')
    for command in WORK_NATIVE_MODEL_COMMANDS:
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'work/native model controls must execute exactly once in repository-truth')
    require(code_lines(lanes['protocol-contract']).count(W1_LIFECYCLE_NATIVE_CONTROLS) == 1
            and code_lines(script).count(W1_LIFECYCLE_NATIVE_CONTROLS) == 1,
            'native lifecycle cost controls must execute exactly once in protocol-contract')
    for command in (
            'python3 scripts/ci/test_pq_authority_effect_register.py',
            'python3 scripts/ci/pq_authority_effect_register.py',
            "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_root_recovery_policy_v1.py' -v"):
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'PQ authority effect and root recovery controls must execute exactly once in repository-truth')
    require(MODEL_WINDOW_ORACLE in lanes['protocol-contract'] and script.count(MODEL_WINDOW_ORACLE) == 1,
            'model-window history arithmetic and frozen evidence checks must execute once in protocol-contract')
    require(MODEL_WINDOW_ORACLE + EVALUATION_QUORUM_ORACLE in lanes['protocol-contract'] and
            all(script.count(command) == 1 for command in EVALUATION_QUORUM_ORACLE.splitlines(keepends=True)),
            'evaluation quorum oracle and exact retained vectors must execute once in protocol-contract without rewriting fixtures')
    for block, lane, label in [(MODEL_EVOLUTION_ORACLES, 'protocol-contract', 'model evolution and task-window oracles'),
                               (COST_BOUNDARY_READERS, 'repository-truth', 'work-cost and DAA reader controls'),
                               (ORIGINAL_CAMPAIGN_READER, 'repository-truth', 'original campaign source-pinned reader controls')]:
        require(block in lanes[lane] and all(script.count(command) == 1 for command in block.splitlines(keepends=True)),
                label + ' must execute once in their original lane')
    require(NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE in lanes['protocol-contract'] and
            script.count(ACCOUNT_ARCHIVE_ORACLE) == 1,
            'native archive vectors and the independent read-only oracle must execute after their actual release build')
    require(NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE + ACCOUNT_EXECUTION_ORACLE in lanes['protocol-contract'] and
            script.count(ACCOUNT_EXECUTION_ORACLE) == 1,
            'native account execution, complete state witness and independent JSON oracles must execute once after the actual Node release build')
    require(NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE + ACCOUNT_EXECUTION_ORACLE +
            GSC2_SYNTHETIC_ORACLE in lanes['protocol-contract'],
            'GSC2 synthetic counterexamples must follow the unchanged native archive/execution oracle sequence')
    expected = ('    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check\n'
                '    python3 scripts/ci/run_supply_chain.py\n' + MODEL_OBSERVATION_BLOCK +
                NATIVE_RELEASE_BLOCK + RUST_DOCS + RUST_CLIPPY)
    require(code_lines(lanes['rust-baseline']) == code_lines(expected),
            'one actual workspace test must collect fresh native observations, check every independent reader, explicitly execute all four release controls, then run docs/Clippy outside exports')
    require(NATIVE_GROWTH_RELEASE_BLOCK in lanes['rust-baseline'] and
            all(code_lines(script).count(command) == 1
                for command in code_lines(NATIVE_GROWTH_RELEASE_BLOCK)),
            'native 65537-account growth must execute once in rust-baseline with a fresh export, exact nonempty release test and independent SQLite readback')
    require(script.count('TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY') ==
            NATIVE_GROWTH_RELEASE_BLOCK.count('TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY'),
            'native growth export selector must remain in its one release/readback block')
    require(NATIVE_GROWTH_V2_RELEASE_BLOCK in lanes['rust-baseline'] and
            all(code_lines(script).count(command) == 1
                for command in code_lines(NATIVE_GROWTH_V2_RELEASE_BLOCK)),
            'bounded native growth must execute once in rust-baseline with its fresh export and exact nonempty release test')
    require(script.count('TRNM_NATIVE_GROWTH_V2_EXPORT_DIR') ==
            NATIVE_GROWTH_V2_RELEASE_BLOCK.count('TRNM_NATIVE_GROWTH_V2_EXPORT_DIR'),
            'bounded native growth export selector must remain in its one release block')
    require(script.count(RUST_ALL_TARGETS) == 1, 'the full workspace observation suite must execute exactly once')
    for selector in ['TRNM_MODEL_COMPOSITION_VECTORS', 'TRNM_MODEL_COMPOSITION_RUN_ID',
                     'TRNM_OBLIGATION_RANGE_VECTORS', 'TRNM_ZERO_PAIRED_PREFIX_OUTPUT',
                     'TRNM_DAA_EVIDENCE_DIR', 'TRNM_JOINT_DAA_EVIDENCE_DIR']:
        require(script.count(selector) == MODEL_OBSERVATION_BLOCK.count(selector),
                'native observation selectors must remain inside the single test/oracle subshell')
    require(script.count(NATIVE_RELEASE_BLOCK) == 1,
            'full-capacity, reference-growth, bounded-growth and account-verification release controls must execute once sequentially')
    for command in CREDIT_MODEL_COMMANDS:
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'credit model controls must execute exactly once in repository-truth')
    for command in ('python3 scripts/ci/test_w1_qrom_current_implementation_audit.py',
                    'python3 scripts/w1_qrom_current_implementation_audit.py'):
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'current W1 source mapping controls must execute exactly once in repository-truth')
    # Preserve the preceding specific refusal diagnostics when an unrelated
    # required command is moved into this prefix.
    require(code_lines(lanes['repository-truth'])[:3] == code_lines(CREDIT_MODEL_PREFIX),
            'credit model prefix must execute immediately after preflight without shell control flow')
    repository_commands = code_lines(re.sub(r'\\\n[ \t]*', ' ', lanes['repository-truth']))
    expected_repository_commands = code_lines(
        re.sub(r'\\\n[ \t]*', ' ', REPOSITORY_TRUTH_BLOCK))
    require(repository_commands == expected_repository_commands,
            'repository-truth controls must retain a straight-line command sequence')
    require(code_lines(lanes['protocol-contract']) == code_lines(PROTOCOL_CONTRACT_BLOCK),
            'protocol-contract must retain its complete straight-line command sequence without shell control flow that skips tests or swallows failures')
    require(code_lines(lanes['repository-truth']) == code_lines(REPOSITORY_TRUTH_BLOCK),
            'W1 post-win controls and all retained repository-truth commands require one straight-line lane without skipped or swallowed failures')
    require(code_lines(lanes['external-evidence-contract']) == code_lines(EXTERNAL_EVIDENCE_CONTRACT_BLOCK),
            'external-evidence-contract must retain its complete straight-line command sequence without skipped or swallowed failures')
    for command in ('python3 scripts/ci/check_completion_evidence.py --historical',
                    'python3 scripts/ci/test_completion_evidence.py'):
        require(code_lines(lanes['external-evidence-contract']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'historical completion evidence controls must execute exactly once in external-evidence-contract')
    dispatch_prefix = ('#!/usr/bin/env bash\nset -euo pipefail\n'
                       'export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"\n'
                       'case "${1:?required job}" in\n')
    dispatch_suffix = "  *) printf '%s\\n' 'unknown CI job' >&2; exit 2 ;;\nesac\n"
    reconstructed = dispatch_prefix + ''.join(
        '  ' + name + ')\n' + block + '    ;;\n' for name, block in pairs) + dispatch_suffix
    require(script == reconstructed,
            'straight-line lane dispatch must not wrap or swallow the selected lane')


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError('CI contract: ' + message)


def check_from_zero_host_call(text: str, exact_block: str) -> None:
    require(text.count('python3 scripts/ci/run_from_zero_native.py') == 1
            and text.count('python3 scripts/ci/run_from_zero_host.py') == 1
            and exact_block in text,
            'one unchanged from-zero argv must run through the original fixed Host parent')


HISTORY_HOST_STEPS = '''      - name: Build the original long-history test separately from measurement
        id: history_build
        if: ${{ !cancelled() && steps.source.outcome == 'success' && steps.toolchain.outcome == 'success' && matrix.campaign == 'history' }}
        run: python3 scripts/ci/run_history_native.py --prepare --out "$TRNM_CI_RECEIPT_DIR/history-native"
      - name: Execute 4105 real work blocks and paid public full sync
        if: ${{ !cancelled() && steps.history_build.outcome == 'success' && matrix.campaign == 'history' }}
        run: python3 scripts/ci/run_from_zero_host.py -- python3 scripts/ci/run_history_native.py --out "$TRNM_CI_RECEIPT_DIR/history-native"
'''
PUSH_SOURCE_HEAD = "${{ github.event_name == 'push' && needs.push-source-context.outputs.head || github.event.pull_request.head.sha }}"
PUSH_SOURCE_BASE = "${{ github.event_name == 'push' && needs.push-source-context.outputs.base || github.event.pull_request.base.sha }}"
PUSH_SOURCE_MERGE = "${{ github.event_name == 'push' && needs.push-source-context.outputs.merge || github.sha }}"
PUSH_SOURCE_SELECTED = ("${{ matrix.source == 'head' && (github.event_name == 'push' && "
    "needs.push-source-context.outputs.head || github.event.pull_request.head.sha) || "
    "(github.event_name == 'push' && needs.push-source-context.outputs.merge || github.sha) }}")
PUSH_SOURCE_JOB_GUARD = (
    "    needs: push-source-context\n"
    "    if: ${{ !cancelled() && (github.event_name == 'pull_request' || "
    "needs.push-source-context.result == 'success') }}\n")
HISTORY_EXPECTED_SOURCE = "      TRNM_EXPECTED_SOURCE_SHA: " + PUSH_SOURCE_SELECTED + "\n"
PUSH_SOURCE_LANES = {
    'pon-priority-acceptance.yml': {
        'native-priorities': '$RUNNER_TEMP/priority-observations'},
    'pon-w1-work-security.yml': {
        'false-trace-reuse': '$RUNNER_TEMP/w1-security-$SOURCE_KIND-${{ matrix.arch }}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT',
        'legal-strategy': '$RUNNER_TEMP/$LEGAL_CAPTURE_PREFIX-$SOURCE_KIND-${{ matrix.arch }}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT',
        'legal-factorial': '$RUNNER_TEMP/w1-legal-factorial-$SOURCE_KIND-${{ matrix.arch }}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT',
        'fresh-challenge-service': '$RUNNER_TEMP/w1-fresh-service-$SOURCE_KIND-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT',
        'rank-batch-v5': '$RUNNER_TEMP/w1-rank-batch-$SOURCE_KIND-${{ matrix.arch }}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT'},
}


def check_integration_push_workflow(text: str, name: str) -> None:
    """The added event must preserve PR sources and every original native lane."""
    header, body = text.split('\njobs:\n', 1)
    events = header.split('on:\n', 1)[1].split('\npermissions:', 1)[0]
    require(re.findall(r'(?m)^  ([a-z_]+):', events) == ['push', 'pull_request']
            and events.startswith('  push:\n    branches:\n      - fix/chain-six-axis-performance-20261103\n'),
            'only the original integration push is added alongside pull_request')
    require(all(value not in text for value in ('pull_request_target', 'continue-on-error',
                'contents: write', 'GITHUB_EVENT_NAME=', 'GITHUB_SHA=')),
            'push cannot gain writes, hide failures or impersonate a PR event')
    pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)', body)
    jobs, lanes = dict(pairs), PUSH_SOURCE_LANES[name]
    retained = {'retained-pressure-failure'} if name == 'pon-priority-acceptance.yml' else set()
    require(len(jobs) == len(pairs) and set(jobs) == set(lanes) | retained | {'push-source-context'},
            'all original jobs and one push resolver remain explicit')
    resolver = jobs['push-source-context']
    require("    if: github.event_name == 'push'\n" in resolver
            and '          ref: ${{ github.sha }}\n' in resolver
            and '          fetch-depth: 0\n' in resolver
            and '          persist-credentials: false\n' in resolver
            and 'integration_push_source.py resolve --output "$RUNNER_TEMP/integration-push-source/context.json"' in resolver
            and 'python3 scripts/ci/test_integration_push_source.py' in resolver
            and 'verify_ci_source.py --kind head --expected-head "$GITHUB_SHA"' in resolver
            and '        if: always()\n' in resolver,
            'one real push resolver freezes and retains independently checked source')
    for key in ('head', 'base', 'merge', 'context', 'context_sha256'):
        require(f'      {key}: ${{{{ steps.resolve.outputs.{key} }}}}\n' in resolver,
                'source outputs come only from the resolver')
    for lane, output in lanes.items():
        block = jobs[lane]
        require(PUSH_SOURCE_JOB_GUARD in block and 'source: [head, prospective-merge]\n' in block,
                'native head and merge lanes require their push resolver without skipping PRs')
        for key, expression in (('HEAD', PUSH_SOURCE_HEAD), ('BASE', PUSH_SOURCE_BASE),
                                ('MERGE', PUSH_SOURCE_MERGE)):
            require('      EXPECTED_' + key + ': ' + expression + '\n' in block,
                    'native lane preserves PR inputs and exact frozen push outputs')
        selected_key = 'TRNM_EXPECTED_SOURCE_SHA' if lane == 'native-priorities' else 'EXPECTED_SOURCE'
        require('      ' + selected_key + ': ' + PUSH_SOURCE_SELECTED + '\n' in block,
                'selected head or merge is bound to its source context')
        require("        if: github.event_name == 'push'\n" in block
                and 'PUSH_SOURCE_CONTEXT: ${{ needs.push-source-context.outputs.context }}\n' in block
                and 'PUSH_SOURCE_CONTEXT_SHA256: ${{ needs.push-source-context.outputs.context_sha256 }}\n' in block
                and block.count('integration_push_source.py materialize --kind "$SOURCE_KIND" --context-json "$PUSH_SOURCE_CONTEXT" --context-sha256 "$PUSH_SOURCE_CONTEXT_SHA256" --output "$RUNNER_TEMP/integration-push-context.json"') == 1
                and block.count('python3 scripts/ci/verify_ci_source.py "${args[@]}"') == 2,
                'each push lane reproduces the real merge before both original source checks')
        require("        if: always() && github.event_name == 'push'\n" in block
                and '          push_context_out="' + output + '"\n' in block
                and '          cp "$RUNNER_TEMP/integration-push-context.json" "$push_context_out/push-source-context.json"\n' in block,
                'each lane retains its context even after native or materialization failure')
        if lane == 'native-priorities':
            require('runner: [ubuntu-24.04, ubuntu-24.04-arm]\n' in block
                    and 'campaign: [service-model, state, history]\n' in block,
                    'all twelve original priority lanes remain')
        elif lane != 'fresh-challenge-service':
            require('arch: [x64, arm64]\n' in block, 'both original W1 architectures remain')
    require('version: [v1, v2]\n' in jobs.get('legal-strategy', '')
            or name == 'pon-priority-acceptance.yml', 'both original legal-strategy versions remain')


def check_history_host_call(text: str) -> str:
    require(text.count(HISTORY_HOST_STEPS) == 1
            and text.count('python3 scripts/ci/run_history_native.py') == 2,
            'history retains one exact build and one whole native test under the fixed Host')
    require(text.count(HISTORY_EXPECTED_SOURCE) == 1
            and text.count('    timeout-minutes: 180\n') == 1,
            'history retains the event-selected source and original 180-minute job budget')
    # Remove only the two exact checked history steps. The original from-zero
    # call must still occur exactly once; no arbitrary second Host command is allowed.
    return text.replace(HISTORY_HOST_STEPS, '')


def check_from_zero_host_callsites(root: Path) -> None:
    for name in PUSH_SOURCE_LANES:
        check_integration_push_workflow((root / '.github/workflows' / name).read_text(), name)
    command = ('python3 scripts/ci/run_from_zero_host.py -- '
               'python3 scripts/ci/run_from_zero_native.py --out ')
    workflow_command = '        run: ' + command + '"$TRNM_CI_RECEIPT_DIR/from-zero-native"\n'
    check_from_zero_host_call((root / 'scripts/ci/ci_job.sh').read_text(),
        '  protocol-contract)\n' + PQ_MIGRATION_CONFORMANCE_PREFIX + '    ' + command
        + '"${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/from-zero-native"\n')
    check_from_zero_host_call((root / '.github/workflows/trnm-required-baseline.yml').read_text(),
        '      - name: Execute exact native from-zero service controls\n'
        '        if: always()\n' + workflow_command)
    priority = check_history_host_call((root / '.github/workflows/pon-priority-acceptance.yml').read_text())
    check_from_zero_host_call(priority,
        '      - name: Execute original release from-zero controls\n'
        "        if: ${{ !cancelled() && steps.source.outcome == 'success' && "
        "steps.toolchain.outcome == 'success' && matrix.campaign == 'service-model' }}\n"
        + workflow_command)
    require('        run: python3 scripts/ci/test_from_zero_host_ci.py\n' in
            (root / '.github/workflows/trnm-required-baseline.yml').read_text(),
            'required repository-truth retains public Host CI refusal controls')


def check_w1_reuse_v3(block: str) -> None:
    # This explicit observation lane cannot replace any retained work/cost gate.
    # Exact steps bind the original runner, budgets and fail-closed raw reader.
    require(block == W1_REUSE_V3_JOB.split("\n", 1)[1],
            'four exact W1 V3 head/merge native lanes with retained failure artifacts')


def check_inline_source_pins(root: Path) -> int:
    """Check existing literal blob guards before CI spends a native build.

    This does not add pins or authenticate source execution. The workflow's
    original guard remains authoritative; a reviewed source edit must update
    its corresponding literal rather than silently skipping the guard.
    """
    count = 0
    pattern = re.compile(r'test "\$\(git hash-object ([A-Za-z0-9_./-]+)\)" = ([0-9a-f]{40})')
    for workflow in sorted((root / '.github/workflows').glob('*.yml')):
        for line_number, line in enumerate(workflow.read_text().splitlines(), 1):
            line = line.strip()
            if line.startswith('#') or 'git hash-object' not in line:
                continue
            context = f'{workflow.relative_to(root)}:{line_number}'
            match = pattern.fullmatch(line)
            require(match is not None, 'unsupported inline source guard: ' + context)
            path, expected = match.groups()
            require(not path.startswith('/') and all(part not in ('', '.', '..')
                    for part in path.split('/')), 'noncanonical inline source path: ' + context)
            source = root / path
            require(source.is_file() and not source.is_symlink(),
                    'missing regular inline source: ' + context)
            raw = source.read_bytes()
            actual = hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw,
                                  usedforsecurity=False).hexdigest()
            require(actual == expected, f'inline source pin differs: {context}: {path}: '
                    f'expected {expected}, observed {actual}')
            count += 1
    return count


def check_pq_release_authority_controls(root: Path) -> dict:
    """Pin the complete release roster and its actual hosted execution wiring.

    This is a source contract, not a native test observation. The workflow must
    independently compare the real binary registry and read back each exact run.
    The separate Python suite is explicitly limited to codec/policy test doubles.
    """
    for relative in (PQ_RELEASE_WORKFLOW, PQ_RELEASE_MANIFEST, *PQ_ROOT_HARNESS_FILES):
        source = root / relative
        require(source.is_file() and not source.is_symlink(),
                'PQ release controls require a regular source: ' + relative)
    manifest = json.loads((root / PQ_RELEASE_MANIFEST).read_text())
    counts = {group: count for group, (count, _) in PQ_RELEASE_GROUPS.items()}
    counts['complete_release'] = 55
    require(isinstance(manifest, dict)
            and manifest.get('schema') == 'trnm-pq-release-authority-required-tests-v2'
            and manifest.get('package') == 'trnm-release-bundle'
            and manifest.get('harness') == 'lib'
            and manifest.get('platform_scope') == 'unix'
            and manifest.get('scope') == PQ_RELEASE_SCOPE
            and isinstance(manifest.get('expected_controls'), dict)
            and manifest['expected_controls'] == counts
            and all(type(value) is int for value in manifest['expected_controls'].values())
            and all(manifest.get(key) is False for key in (
                'authorization_results_cached', 'signature_results_cached', 'performance_qualified',
                'production_activation', 'consensus_authority', 'whole_chain_quantum_security_qualified')),
            'PQ release manifest must retain the exact Unix 37 + 6 + 9 + 3 partition and limited scope')
    groups = {}
    for group, (count, expected) in PQ_RELEASE_GROUPS.items():
        names = manifest.get(group + '_tests')
        require(isinstance(names, list) and len(names) == count
                and all(isinstance(name, str) and re.fullmatch(
                    r'[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*', name) for name in names)
                and len(set(names)) == count
                and hashlib.sha256(('\n'.join(names) + '\n').encode()).hexdigest() == expected,
                'PQ release reviewed test names changed: ' + group)
        groups[group] = set(names)
    complete = manifest.get('complete_release_tests')
    require(sum(len(names) for names in groups.values()) == len(set().union(*groups.values())) == 55
            and complete == sorted(set().union(*groups.values())),
            'PQ release complete registry must contain exactly all 55 distinct reviewed Unix tests')

    module = ast.parse((root / PQ_ROOT_HARNESS_FILES[1]).read_text())
    classes = [node for node in module.body
               if isinstance(node, ast.ClassDef) and node.name == 'RootQuorumResearchTests']
    require(len(classes) == 1, 'PQ root harness requires its one explicit test-double class')
    names = sorted(node.name for node in classes[0].body
                   if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
    require(len(names) == len(set(names)) == 18
            and hashlib.sha256(('\n'.join(names) + '\n').encode()).hexdigest()
            == PQ_ROOT_HARNESS_NAMES_SHA256,
            'PQ root harness must retain the exact 18 codec/policy test doubles')

    text = (root / PQ_RELEASE_WORKFLOW).read_text()
    header, separator, body = text.partition('\njobs:\n')
    require(bool(separator), 'PQ workflow requires an explicit jobs mapping')
    paths = re.findall(r'^      - ([A-Za-z0-9_./*-]+)$', header, re.M)
    for relative in ('trillionnium/**', PQ_RELEASE_MANIFEST, PQ_RELEASE_WORKFLOW,
                     *PQ_ROOT_HARNESS_FILES, 'scripts/ci/check_ci_contract.py',
                     'scripts/ci/test_ci_contract.py', 'scripts/ci/check_required_native_test.py',
                     'scripts/ci/pinned_native_process.py'):
        require(paths.count(relative) == 1,
                'PQ workflow must trigger for each release/harness control source: ' + relative)
    pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)', body)
    jobs = dict(pairs)
    job = jobs.get('primitive-interoperability', '')
    require(len(jobs) == len(pairs) and job.startswith(PQ_RELEASE_JOB_HEADER)
            and 'continue-on-error' not in job and not re.search(r'^    if:', job, re.M),
            'PQ release controls retain both native runners and head/merge sources without skipped failures')
    for step in (PQ_RELEASE_AUTHORITY_STEP, PQ_ROOT_HARNESS_STEP):
        require(job.count(step) == text.count(step) == 1,
                'PQ release registry, exact execution and harness readback must remain complete')
    require(job.count(PQ_RELEASE_REGRESSION_COMMAND) == 1
            and job.index(PQ_RELEASE_REGRESSION_COMMAND) < job.index(PQ_RELEASE_AUTHORITY_STEP)
            < job.index(PQ_ROOT_HARNESS_STEP),
            'PQ complete component regression precedes all 55 exact Unix executions and 18 Python controls')
    return {'complete_release': 55, 'platform_scope': 'unix', 'groups': {group: count for group, (count, _) in PQ_RELEASE_GROUPS.items()},
            'python_test_doubles': 18, 'tests_executed': False}


def validate(root: Path = ROOT) -> dict:
    # Discovery can exit successfully with zero tests when a pattern disappears.
    # These mandatory files are executed explicitly and must also exist at review.
    for name in ('test_useful_cell_numeric_v1.py', 'test_useful_cell_relation_v1.py',
                 'test_useful_cell_execution_v2.py', 'test_useful_cell_relation_v2.py',
                 'test_useful_cell_relation_v2_adversarial.py', 'test_useful_cell_source_guard_v2.py',
                 'test_useful_cell_multimodal_execution_v3.py',
                 'test_useful_cell_multimodal_relation_v3.py',
                 'test_lifecycle_cost_v1.py', 'test_cell_lottery_cost_audit_v1.py',
                 'test_service_work_settlement_v1.py'):
        source = root / 'formal/pon-nakamoto-v1' / name
        require(source.is_file() and not source.is_symlink(),
                'required useful Cell test source is missing: ' + name)
    inline_source_pins = check_inline_source_pins(root)
    pq_release_authority_controls = check_pq_release_authority_controls(root)
    check_from_zero_host_callsites(root)
    check_w1_postwin_workflow((root / '.github/workflows/pon-w1-transparent-profile.yml').read_text())
    text = (root / WORKFLOW).read_text()
    body = text.split('\njobs:\n', 1)
    require(len(body) == 2, 'one explicit jobs mapping required')
    pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)', body[1])
    jobs = dict(pairs)
    runtime_requirements = (root / 'scripts/ci/runtime-release-requirements.txt').read_text()
    runtime_pins = '\n'.join(line for line in runtime_requirements.splitlines()
                             if line.strip() and not line.lstrip().startswith('#'))
    require(runtime_pins == RUNTIME_RELEASE_REQUIREMENT and RUNTIME_RELEASE_REQUIREMENT in
            (root / 'scripts/ci/model-runtime-cpu-requirements.txt').read_text(),
            'runtime verifier reuses exactly the reviewed packaging wheel and hash')
    for job, step, execution in (
            ('repository-truth', RUNTIME_RELEASE_PYTHON,
             '      - name: Run actual repository-truth checks\n'),
            ('prospective-merge', MERGE_RUNTIME_RELEASE_PYTHON,
             '      - name: Execute the same lane on the prospective merge\n')):
        require(jobs.get(job, '').count(step) == 1 and step + execution in jobs[job],
                'both repository-truth lanes install the pinned verifier dependency before execution')
    required = json.loads((root / 'config/repository-policy-v1.json').read_text())['required_check_names']
    require(len(jobs) == len(pairs) and set(jobs) == set(required) |
            {'prospective-merge', 'cross-arch-cost', 'cross-arch-cost-consistency',
             'rust-baseline-shards', 'prospective-rust-shards', 'prospective-rust-baseline',
             'cross-arch-w1-reuse-v3'},
            'required head jobs, separate merge matrix and actual cross-architecture costs must remain explicit')
    require('continue-on-error' not in text and 'pull_request_target' not in text and
            'contents: write' not in text and 'self-hosted' not in text,
            'untrusted source may not gain privilege or discard failures')
    require('  contents: read\n' in text, 'read-only repository permission')
    for name, block in jobs.items():
        expected_runner = '${{ matrix.runner }}' if name in {'cross-arch-cost', 'cross-arch-w1-reuse-v3'} else 'ubuntu-24.04'
        require('    runs-on: ' + expected_runner + '\n' in block, name + ' hosted runner')
        require('uses: ' + CHECKOUT in block and '          fetch-depth: 0\n' in block and
                '          persist-credentials: false\n' in block and
                '          ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}\n' in block,
                name + ' immutable credential-free checkout')
        if name not in {'cross-arch-cost-consistency', 'rust-baseline', 'prospective-rust-baseline'}:
            require(block.count('name: Set isolated Cargo paths after runner allocation') == 1,
                    name + ' runner-stage isolation')
            require(block.count('"$RUNNER_TEMP" "$GITHUB_JOB" >> "$GITHUB_ENV"') == 2,
                    name + ' isolated Cargo directories')
        require('uses: ' + UPLOAD in block and '        if: always()\n' in block and
                '          if-no-files-found: error\n' in block,
                name + ' retained observations on success and failure')
        if name not in {'prospective-merge', 'prospective-rust-shards', 'prospective-rust-baseline',
                        'cross-arch-w1-reuse-v3'}:
            require(block.count('verify_ci_source.py --kind head --expected-head "$TRNM_EXPECTED_SOURCE_SHA"') == 2,
                    name + ' exact head before and after execution')
        if name in set(required) - {'rust-baseline'}:
            require(not re.search(r'^    if:', block, re.M), name + ' cannot be conditionally skipped')
            require('        run: bash scripts/ci/ci_job.sh ' + name + '\n' in block,
                    name + ' must execute its actual lane')
    check_w1_reuse_v3(jobs['cross-arch-w1-reuse-v3'])
    costs = jobs['cross-arch-cost']
    require(not re.search(r'^    if:', costs, re.M), 'native architecture execution cannot be skipped')
    require(f'    timeout-minutes: {COST_JOB_TIMEOUT_MINUTES}\n' in costs and
            '      fail-fast: false\n' in costs,
            'architecture job must cover four generation suites and the separate rejection experiment')
    require(COST_JOB_OVERHEAD_SECONDS >= 27 * 60 and
            COST_JOB_TIMEOUT_MINUTES * 60 >= cost_job_budget_seconds(),
            'all generation/rejection capture budgets, termination grace and setup/source/artifact margin must fit')
    require('''        include:
          - arch: x64
            runner: ubuntu-24.04
          - arch: arm64
            runner: ubuntu-24.04-arm
''' in costs, 'two explicit native hosted runner architectures required')
    require('      TRNM_COST_RUNNER_LABEL: ${{ matrix.runner }}\n' in costs and
            '        run: rustup toolchain install 1.95.0 --profile minimal\n' in costs,
            'observed runner label and pinned native release compiler required')
    require('        run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}"\n' in costs,
            'architecture names are not a substitute for native cost execution')
    require(ZERO_RUN_STEP in costs and text.count(ZERO_RUN_STEP) == 1,
            'separate zero locality native execution must run once in each existing architecture job, including after reused failure')
    require(ZERO_RUN_STEP + ONE_ZERO_RUN_STEP in costs and text.count(ONE_ZERO_RUN_STEP) == 1,
            'one-zero locality must run once after the zero suite, including after either preceding suite failed')
    require(ONE_ZERO_RUN_STEP + MAINTENANCE_RUN_STEP in costs and text.count(MAINTENANCE_RUN_STEP) == 1,
            'fixed maintenance must execute once after the three retained suites including their failure paths')
    require(MAINTENANCE_RUN_STEP + REJECTION_RUN_STEP in costs and text.count(REJECTION_RUN_STEP) == 1,
            'actual legal/Transcript/Product measurements must execute after retained generation suites even on failure')
    require('          name: cost-${{ matrix.arch }}-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}\n' in costs,
            'architecture artifacts must be bound to the same head and attempt')
    comparison = jobs['cross-arch-cost-consistency']
    require('    needs: cross-arch-cost\n    if: always()\n' in comparison,
            'comparison must inspect both success and failure outcomes')
    require('uses: ' + DOWNLOAD in comparison and
            '          pattern: cost-*-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}\n' in comparison and
            '          merge-multiple: false\n' in comparison,
            'comparison must retrieve both actual current-run artifacts without overwriting either')
    require('        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" '
            '--expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output '
            '"$RUNNER_TEMP/ci-observations/cross-arch-comparison.json"\n' in comparison,
            'same-source cross-architecture streams must be checked from actual artifacts')
    require(ZERO_COMPARE_STEP in comparison and text.count(ZERO_COMPARE_STEP) == 1,
            'separate zero locality comparison must inspect actual current-run artifacts even after reused comparison failure')
    require(ZERO_COMPARE_STEP + ONE_ZERO_COMPARE_STEP in comparison and text.count(ONE_ZERO_COMPARE_STEP) == 1,
            'one-zero comparison must inspect its own current-run artifacts after the zero comparison even on earlier failure')
    require(ONE_ZERO_COMPARE_STEP + MAINTENANCE_COMPARE_STEP in comparison and
            text.count(MAINTENANCE_COMPARE_STEP) == 1,
            'fixed maintenance comparison must inspect its separate current-run artifacts after earlier failure')
    require(MAINTENANCE_COMPARE_STEP + REJECTION_COMPARE_STEP in comparison and
            text.count(REJECTION_COMPARE_STEP) == 1,
            'actual rejection comparison must bind both native architectures to this head/run/attempt even on earlier failure')
    merge = jobs['prospective-merge']
    require(re.findall(r'^    timeout-minutes: (.+)$', jobs['rust-baseline'], re.M) == ['180'],
            'the complete head Rust suite requires its explicit 180-minute job budget')
    require(re.findall(r'^    timeout-minutes: (.+)$', merge, re.M) ==
            ["${{ matrix.lane == 'rust-baseline' && 180 || 45 }}"],
            'the merge Rust suite requires the same 180-minute budget; other merge lanes retain 45 minutes')
    require("    if: github.event_name == 'pull_request'\n" in merge, 'merge lane event boundary')
    require('      fail-fast: false\n' in merge, 'all merge lanes retain their outcomes')
    lanes = re.search(r'^        lane: \[([^\]]+)\]$', merge, re.M)
    require(lanes is not None and {p.strip() for p in lanes[1].split(',')} == set(required) - {'rust-baseline'},
            'prospective merge retains four lanes; required Rust uses its separate fail-closed fan-in')
    for line in ['TRNM_EXPECTED_SOURCE_SHA: ${{ github.sha }}',
                 'TRNM_EXPECTED_CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}',
                 'TRNM_EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha }}']:
        require('      ' + line + '\n' in merge, 'merge event identity binding')
    command = ('verify_ci_source.py --kind prospective-merge --expected-head "$TRNM_EXPECTED_CANDIDATE_SHA" '
               '--expected-base "$TRNM_EXPECTED_BASE_SHA" --expected-merge "$TRNM_EXPECTED_SOURCE_SHA"')
    require(merge.count(command) == 2, 'merge parents and source checked before and after execution')
    require('        run: bash scripts/ci/ci_job.sh "${{ matrix.lane }}"\n' in merge,
            'merge uses actual lane execution, not only a source checker')
    # Both required names remain real jobs, even when a dependency failed or
    # was cancelled/skipped. A receipt cannot replace the aggregate job result.
    for kind, worker, fanin in [('head', 'rust-baseline-shards', 'rust-baseline'),
                                ('prospective-merge', 'prospective-rust-shards', 'prospective-rust-baseline')]:
        work, gate = jobs[worker], jobs[fanin]
        for block in (work, gate):
            require(re.findall(r'^    timeout-minutes: (.+)$', block, re.M) == ['180'],
                    'each Rust shard and fan-in retains its original 180-minute budget')
        event = "github.event_name == 'pull_request'"
        conditions = re.findall(r'^    if: (.+)$', work, re.M)
        require(conditions == ([event] if kind == 'prospective-merge' else []), 'Rust shard event boundary')
        condition = "${{ always() && " + event + " }}" if kind == 'prospective-merge' else 'always()'
        require(re.findall(r'^    if: (.+)$', gate, re.M) == [condition] and
                re.findall(r'^    needs: (.+)$', gate, re.M) == [worker], 'Rust fan-in must run after all outcomes')
        require(re.findall(r'^    name: (.+)$', gate, re.M) ==
                ['prospective-merge (rust-baseline)' if kind == 'prospective-merge' else 'rust-baseline'],
                'original required Rust check name')
        require('      fail-fast: false\n      matrix:\n        shard: [runtime, quality]\n' in work and
                '    strategy:' not in gate, 'both required Rust shards execute without fail-fast')
        args = '--kind head --candidate "$TRNM_EXPECTED_SOURCE_SHA" --tested "$TRNM_EXPECTED_SOURCE_SHA"'
        if kind == 'prospective-merge':
            args = '--kind prospective-merge --candidate "$TRNM_EXPECTED_CANDIDATE_SHA" --base "$TRNM_EXPECTED_BASE_SHA" --tested "$TRNM_EXPECTED_SOURCE_SHA"'
            for block in (work, gate):
                for line in ['TRNM_EXPECTED_SOURCE_SHA: ${{ github.sha }}',
                             'TRNM_EXPECTED_CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}',
                             'TRNM_EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha }}']:
                    require('      ' + line + '\n' in block, 'Rust shard merge identity')
                require(block.count(command) == 2, 'Rust merge checked before and after')
        run = 'python3 scripts/ci/rust_baseline_shards.py run ' + args + ' --shard "${{ matrix.shard }}" --output "$RUNNER_TEMP/ci-observations/rust-shard.json"'
        check = 'python3 scripts/ci/rust_baseline_shards.py check ' + args + ' --inputs "$RUNNER_TEMP/rust-shards" --dependency-result "$TRNM_RUST_SHARD_RESULT" --output "$RUNNER_TEMP/ci-observations/rust-fanin.json"'
        require('      - name: Run retained Rust shard\n        run: ' + run + '\n' in work and
                work.count('rust_baseline_shards.py ') == 1, 'real retained Rust shard execution')
        require('      - name: Require both successful exact-source Rust shards\n        if: always()\n        run: ' + check + '\n' in gate and
                gate.count('rust_baseline_shards.py ') == 1 and
                '      TRNM_RUST_SHARD_RESULT: ${{ needs.' + worker + '.result }}\n' in gate,
                'Rust fan-in must require dependency success and exact receipts after failure')
        artifact = 'rust-shard-' + kind + '-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}'
        require('          name: rust-observations-' + kind + '-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}-${{ matrix.shard }}\n' in work and
                '          path: ${{ runner.temp }}/ci-observations/\n' in work and
                '          path: |\n            ${{ runner.temp }}/ci-observations/rust-shard.json\n            ${{ runner.temp }}/ci-observations/rust-shard.sh\n' in work,
                'full native evidence retained separately from lightweight fan-in proof')
        require('          name: ' + artifact + '-${{ matrix.shard }}\n' in work and
                '          pattern: ' + artifact + '-*\n' in gate and
                'uses: ' + DOWNLOAD in gate and '          path: ${{ runner.temp }}/rust-shards/\n' in gate and
                '          merge-multiple: false\n' in gate, 'distinct current-source current-attempt shard artifacts')
    script = (root / 'scripts/ci/ci_job.sh').read_text()
    check_independent_conformance(script, set(required))
    require('    python3 scripts/ci/run_fuzz_smoke.py\n' in script,
            'instrumented fuzz execution missing')
    require(all(SIGNED_STATE_PYTHON in jobs[name] for name in
                ('rust-baseline-shards', 'prospective-rust-shards')) and
            "if: matrix.lane == 'protocol-contract' || matrix.lane == 'external-evidence-contract' || matrix.lane == 'rust-baseline'" in merge,
            'both Rust lanes require the pinned isolated signed-state oracle dependencies')
    require('    python3 scripts/ci/run_supply_chain.py\n' in script,
            'locked dependency checks missing')
    require('    python3 scripts/ci/test_cross_arch_cost.py\n' in script,
            'cross-architecture evidence negative checks missing')
    lane_pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*)\)\n(.*?)(?=^    ;;$)', script)
    for budget_command in ('    python3 scripts/ci/test_pq_lifetime_budget.py\n',
                           '    python3 scripts/ci/pq_lifetime_budget.py\n',
                           '    python3 scripts/ci/test_pq_authority_effect_register.py\n',
                           '    python3 scripts/ci/pq_authority_effect_register.py\n',
                           "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_root_recovery_policy_v1.py' -v\n"):
        require(budget_command in dict(lane_pairs)['repository-truth'] and
                script.count(budget_command) == 1,
                'PQ lifetime and root recovery refusal controls execute once in repository-truth')
    require(RUNTIME_RELEASE_COMMAND in dict(lane_pairs)['repository-truth']
            and script.count(RUNTIME_RELEASE_COMMAND) == 1,
            'runtime material controls execute once with the configured verifier interpreter')
    zero_negative = '    python3 scripts/ci/test_zero_locality_cost.py\n'
    require(zero_negative in dict(lane_pairs)['repository-truth'] and script.count(zero_negative) == 1,
            'zero locality evidence negative checks must execute in repository-truth')
    one_zero_negative = '    python3 scripts/ci/test_one_zero_locality_cost.py\n'
    require(one_zero_negative in dict(lane_pairs)['repository-truth'] and script.count(one_zero_negative) == 1,
            'one-zero locality evidence negative checks must execute in repository-truth')
    maintenance_negative = '    python3 scripts/ci/test_maintenance_cost.py\n'
    require(maintenance_negative in dict(lane_pairs)['repository-truth'] and
            script.count(maintenance_negative) == 1,
            'fixed maintenance evidence negative checks must execute once in repository-truth')
    rejection_negative = '    python3 scripts/ci/test_work_rejection_report.py\n'
    require(rejection_negative in dict(lane_pairs)['repository-truth'] and
            script.count(rejection_negative) == 1,
            'actual rejection cost evidence negatives must execute once in repository-truth')
    for reader in ('test_six_workpackage_native_rosters.py',
                   'test_w1_full_v2_disposition.py',
                   'test_pon_w1_preparation_strategy_reader_v4.py'):
        command = '    python3 scripts/ci/' + reader + '\n'
        require(command in dict(lane_pairs)['repository-truth'] and
                script.count(command) == 1,
                'six-workpackage reader must execute once in repository-truth: ' + reader)
    archive_negative = '    python3 scripts/ci/test_account_archive_conformance.py\n'
    require(archive_negative in dict(lane_pairs)['repository-truth'] and script.count(archive_negative) == 1,
            'archive native/oracle receipt negatives must execute once in repository-truth')
    execution_negative = '    python3 scripts/ci/test_run_account_execution_conformance.py\n'
    require(execution_negative in dict(lane_pairs)['repository-truth'] and script.count(execution_negative) == 1,
            'account execution receipt negatives must execute once in repository-truth')
    require('    python3 scripts/run_public_v3_service_campaign.py --out ' in script,
            'source-bound mixed-service campaign and retained refusal checks missing')
    require(jobs['fuzz-smoke'].count('run: bash scripts/ci/install_ci_tools.sh fuzz') == 1 and
            merge.count('run: bash scripts/ci/install_ci_tools.sh fuzz') == 1, 'pinned fuzz installation missing')
    require(all(jobs[name].count('run: bash scripts/ci/install_ci_tools.sh supply-chain') == 1 for name in
                ('rust-baseline-shards', 'prospective-rust-shards')) and
            merge.count('run: bash scripts/ci/install_ci_tools.sh supply-chain') == 1,
            'pinned dependency auditor installation missing')
    versions = dict(line.split('=', 1) for line in (root / 'scripts/ci/tool-versions.env').read_text().splitlines()
                    if line and not line.startswith('#'))
    require(set(versions) == {'TRNM_CARGO_FUZZ_VERSION', 'TRNM_FUZZ_TOOLCHAIN', 'TRNM_CARGO_DENY_VERSION'},
            'explicit tool inventory')
    require(all(re.fullmatch(r'\d+\.\d+\.\d+', versions[key]) for key in
                ('TRNM_CARGO_FUZZ_VERSION', 'TRNM_CARGO_DENY_VERSION')) and
            re.fullmatch(r'nightly-\d{4}-\d{2}-\d{2}', versions['TRNM_FUZZ_TOOLCHAIN']) is not None,
            'floating toolchain/tool version')
    require((root / 'tests/fuzz/Cargo.lock').is_file(), 'isolated fuzz lockfile missing')
    normal = tomllib.loads((root / 'trillionnium/Cargo.lock').read_text())['package']
    fuzz = tomllib.loads((root / 'tests/fuzz/Cargo.lock').read_text())['package']
    resolved = {}
    for package in normal:
        resolved.setdefault((package['name'], package.get('source')), set()).add(package['version'])
    for package in fuzz:
        key = (package['name'], package.get('source'))
        require(key not in resolved or package['version'] in resolved[key],
                'fuzz must instrument the same shared dependency versions as the native lockfile: ' + package['name'])
    # A lock may preserve every version yet omit a newly required dependency
    # edge of a local crate. Check unconditional nonoptional normal dependencies;
    # dev/target/optional edges remain Cargo's responsibility, not inferred here.
    workspace = tomllib.loads((root / 'trillionnium/Cargo.toml').read_text())
    inherited = workspace.get('workspace', {}).get('dependencies', {})
    local = {}
    for member in workspace['workspace']['members']:
        manifest = tomllib.loads((root / 'trillionnium' / member / 'Cargo.toml').read_text())
        local[manifest['package']['name']] = manifest
    for package in fuzz:
        if package.get('source') is not None or package['name'] not in local:
            continue
        edges = {edge.split(' ', 1)[0] for edge in package.get('dependencies', [])}
        for alias, specification in local[package['name']].get('dependencies', {}).items():
            detail = specification if isinstance(specification, dict) else {}
            if detail.get('optional', False):
                continue
            parent_detail = inherited.get(alias, {}) if detail.get('workspace', False) else {}
            parent_detail = parent_detail if isinstance(parent_detail, dict) else {}
            dependency = detail.get('package', parent_detail.get('package', alias))
            require(dependency in edges,
                    'fuzz lock missing required local dependency edge: '
                    + package['name'] + ' -> ' + dependency)
    return {'head_jobs': len(required), 'merge_lanes': len(required),
            'native_cost_architectures': 2, 'artifact_comparison_jobs': 1,
            'w1_actual_reuse_v3_cells': 4, 'inline_source_pins': inline_source_pins,
            'pq_release_authority_controls': pq_release_authority_controls,
            'tests_executed': False}


if __name__ == '__main__':
    print(json.dumps(validate(), sort_keys=True))
