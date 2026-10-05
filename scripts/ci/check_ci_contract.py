#!/usr/bin/env python3
"""Check the deliberately fixed hosted-CI structure; this does not execute its lanes."""
from __future__ import annotations

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
SIGNED_STATE_PYTHON = '''      - name: Install isolated signed-state oracle Python environment
        run: |
          python3 -m venv "$RUNNER_TEMP/pon-state-env"
          "$RUNNER_TEMP/pon-state-env/bin/python" -m pip install --disable-pip-version-check --only-binary=:all: -r formal/pon-nakamoto-v1/requirements.txt
          echo "$RUNNER_TEMP/pon-state-env/bin" >> "$GITHUB_PATH"
'''
ZERO_RUN_STEP = '''      - name: Execute native zero-matrix locality costs
        if: always()
        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite zero-locality --zero-version 2
'''
ZERO_COMPARE_STEP = '''      - name: Check zero-matrix streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-zero-locality-comparison.json" --suite zero-locality --zero-version 2
'''
ONE_ZERO_RUN_STEP = '''      - name: Execute native one-zero rank-one locality costs
        if: always()
        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite one-zero-locality
'''
ONE_ZERO_COMPARE_STEP = '''      - name: Check one-zero rank-one streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-one-zero-locality-comparison.json" --suite one-zero-locality
'''
MAINTENANCE_RUN_STEP = '''      - name: Execute native fixed maintenance producer and preparation costs
        if: always()
        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite maintenance-paired
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
CONTINUITY_BUILD = '    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee --examples\n'
CONTINUITY_ORIGINAL = '    TRNM_CONTINUITY_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_vectors")" python3 formal/pon-nakamoto-v1/test_continuity.py -v\n'
CONTINUITY_TRANSITIONS = '    TRNM_CONTINUITY_TRANSITIONS_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_transition_vectors")" python3 formal/pon-nakamoto-v1/test_continuity_transitions.py -v\n'
PAIRED_WORK_ORACLE = '    TRNM_PAIRED_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_paired_io")" TRNM_PAIRED_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/paired-work" python3 formal/pon-nakamoto-v1/test_paired_work.py -v\n'
ZERO_WORK_ORACLE = '    TRNM_ZERO_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_zero_io")" TRNM_ZERO_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/zero-work" python3 formal/pon-nakamoto-v1/test_zero_work.py -v\n'
MODEL_WINDOW_ORACLE = '    python3 formal/pon-nakamoto-v1/test_model_window_history.py -v\n'
NODE_EXAMPLE_BUILD = '    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --bins --examples\n'
ACCOUNT_ARCHIVE_ORACLE = ('    python3 formal/pon-nakamoto-v1/test_account_archive_oracle.py -v\n'
                          '    python3 scripts/ci/run_account_archive_conformance.py\n')
ACCOUNT_EXECUTION_ORACLE = ('    python3 formal/pon-nakamoto-v1/test_account_execution_oracle.py -v\n'
                            '    python3 formal/pon-nakamoto-v1/test_state_witness_oracle.py -v\n'
                            '    python3 scripts/ci/run_account_execution_conformance.py\n')
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
      cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features
      unset TRNM_ZERO_PAIRED_PREFIX_OUTPUT
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
      test ! -e "$trnm_native_receipt_root/native-account-verification-cost"
      test ! -L "$trnm_native_receipt_root/native-account-verification-cost"
      test ! -e "$trnm_native_receipt_root/native-account-verification-cost.log"
      test ! -L "$trnm_native_receipt_root/native-account-verification-cost.log"
      TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY="$trnm_native_receipt_root/native-account-verification-cost" cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee "$trnm_native_receipt_root/native-account-verification-cost.log"
    )
'''


def code_lines(text: str) -> list[str]:
    """The fixed lane permits whole-line comments, not alternate shell control flow."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]


def check_independent_conformance(script: str, required: set[str]) -> None:
    require(script.startswith('#!/usr/bin/env bash\nset -euo pipefail\n'),
            'lane execution must propagate actual failures')
    pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*)\)\n(.*?)(?=^    ;;$)', script)
    lanes = dict(pairs)
    require(len(pairs) == len(lanes) and set(lanes) == required, 'exact five executable lane selectors')
    continuity = CONTINUITY_BUILD + CONTINUITY_ORIGINAL + CONTINUITY_TRANSITIONS + PAIRED_WORK_ORACLE + ZERO_WORK_ORACLE
    require(continuity in lanes['protocol-contract'] and script.count(CONTINUITY_ORIGINAL) == 1
            and script.count(CONTINUITY_TRANSITIONS) == 1,
            'continuity and paired-work oracles must execute in protocol-contract after their actual release build')
    require(script.count(PAIRED_WORK_ORACLE) == 1,
            'one native paired-work byte comparison must retain its fresh current-lane output')
    require(script.count(ZERO_WORK_ORACLE) == 1,
            'one native zero-work byte comparison must retain its fresh current-lane output after its release build')
    require(MODEL_WINDOW_ORACLE in lanes['protocol-contract'] and script.count(MODEL_WINDOW_ORACLE) == 1,
            'model-window history arithmetic and frozen evidence checks must execute once in protocol-contract')
    require(NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE in lanes['protocol-contract'] and
            script.count(ACCOUNT_ARCHIVE_ORACLE) == 1,
            'native archive vectors and the independent read-only oracle must execute after their actual release build')
    require(NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE + ACCOUNT_EXECUTION_ORACLE in lanes['protocol-contract'] and
            script.count(ACCOUNT_EXECUTION_ORACLE) == 1,
            'native account execution, complete state witness and independent JSON oracles must execute once after the actual Node release build')
    expected = ('    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check\n'
                '    python3 scripts/ci/run_supply_chain.py\n' + MODEL_OBSERVATION_BLOCK +
                NATIVE_RELEASE_BLOCK + RUST_DOCS + RUST_CLIPPY)
    require(code_lines(lanes['rust-baseline']) == code_lines(expected),
            'one actual workspace test must collect fresh native observations, check every independent reader, explicitly execute both release controls, then run docs/Clippy outside exports')
    require(script.count(RUST_ALL_TARGETS) == 1, 'the full workspace observation suite must execute exactly once')
    for selector in ['TRNM_MODEL_COMPOSITION_VECTORS', 'TRNM_MODEL_COMPOSITION_RUN_ID',
                     'TRNM_OBLIGATION_RANGE_VECTORS', 'TRNM_ZERO_PAIRED_PREFIX_OUTPUT']:
        require(script.count(selector) == MODEL_OBSERVATION_BLOCK.count(selector),
                'native observation selectors must remain inside the single test/oracle subshell')
    require(script.count(NATIVE_RELEASE_BLOCK) == 1,
            'full-capacity and account-verification release controls must execute once sequentially')


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError('CI contract: ' + message)


def validate(root: Path = ROOT) -> dict:
    text = (root / WORKFLOW).read_text()
    body = text.split('\njobs:\n', 1)
    require(len(body) == 2, 'one explicit jobs mapping required')
    pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)', body[1])
    jobs = dict(pairs)
    required = json.loads((root / 'config/repository-policy-v1.json').read_text())['required_check_names']
    require(len(jobs) == len(pairs) and set(jobs) == set(required) |
            {'prospective-merge', 'cross-arch-cost', 'cross-arch-cost-consistency'},
            'required head jobs, separate merge matrix and actual cross-architecture costs must remain explicit')
    require('continue-on-error' not in text and 'pull_request_target' not in text and
            'contents: write' not in text and 'self-hosted' not in text,
            'untrusted source may not gain privilege or discard failures')
    require('  contents: read\n' in text, 'read-only repository permission')
    for name, block in jobs.items():
        expected_runner = '${{ matrix.runner }}' if name == 'cross-arch-cost' else 'ubuntu-24.04'
        require('    runs-on: ' + expected_runner + '\n' in block, name + ' hosted runner')
        require('uses: ' + CHECKOUT in block and '          fetch-depth: 0\n' in block and
                '          persist-credentials: false\n' in block and
                '          ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}\n' in block,
                name + ' immutable credential-free checkout')
        if name != 'cross-arch-cost-consistency':
            require(block.count('name: Set isolated Cargo paths after runner allocation') == 1,
                    name + ' runner-stage isolation')
            require(block.count('"$RUNNER_TEMP" "$GITHUB_JOB" >> "$GITHUB_ENV"') == 2,
                    name + ' isolated Cargo directories')
        require('uses: ' + UPLOAD in block and '        if: always()\n' in block and
                '          if-no-files-found: error\n' in block,
                name + ' retained observations on success and failure')
        if name != 'prospective-merge':
            require(block.count('verify_ci_source.py --kind head --expected-head "$TRNM_EXPECTED_SOURCE_SHA"') == 2,
                    name + ' exact head before and after execution')
        if name in required:
            require(not re.search(r'^    if:', block, re.M), name + ' cannot be conditionally skipped')
            require('        run: bash scripts/ci/ci_job.sh ' + name + '\n' in block,
                    name + ' must execute its actual lane')
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
    require('        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}"\n' in costs,
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
    require(lanes is not None and {p.strip() for p in lanes[1].split(',')} == set(required),
            'prospective merge must execute the same five lanes')
    for line in ['TRNM_EXPECTED_SOURCE_SHA: ${{ github.sha }}',
                 'TRNM_EXPECTED_CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}',
                 'TRNM_EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha }}']:
        require('      ' + line + '\n' in merge, 'merge event identity binding')
    command = ('verify_ci_source.py --kind prospective-merge --expected-head "$TRNM_EXPECTED_CANDIDATE_SHA" '
               '--expected-base "$TRNM_EXPECTED_BASE_SHA" --expected-merge "$TRNM_EXPECTED_SOURCE_SHA"')
    require(merge.count(command) == 2, 'merge parents and source checked before and after execution')
    require('        run: bash scripts/ci/ci_job.sh "${{ matrix.lane }}"\n' in merge,
            'merge uses actual lane execution, not only a source checker')
    script = (root / 'scripts/ci/ci_job.sh').read_text()
    check_independent_conformance(script, set(required))
    require('    python3 scripts/ci/run_fuzz_smoke.py\n' in script,
            'instrumented fuzz execution missing')
    require(SIGNED_STATE_PYTHON in jobs['rust-baseline'] and
            "if: matrix.lane == 'protocol-contract' || matrix.lane == 'external-evidence-contract' || matrix.lane == 'rust-baseline'" in merge,
            'both Rust lanes require the pinned isolated signed-state oracle dependencies')
    require('    python3 scripts/ci/run_supply_chain.py\n' in script,
            'locked dependency checks missing')
    require('    python3 scripts/ci/test_cross_arch_cost.py\n' in script,
            'cross-architecture evidence negative checks missing')
    lane_pairs = re.findall(r'(?ms)^  ([a-z][a-z0-9-]*)\)\n(.*?)(?=^    ;;$)', script)
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
    require(jobs['rust-baseline'].count('run: bash scripts/ci/install_ci_tools.sh supply-chain') == 1 and
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
    return {'head_jobs': len(required), 'merge_lanes': len(required),
            'native_cost_architectures': 2, 'artifact_comparison_jobs': 1, 'tests_executed': False}


if __name__ == '__main__':
    print(json.dumps(validate(), sort_keys=True))
