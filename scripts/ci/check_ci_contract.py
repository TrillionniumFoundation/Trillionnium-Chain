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
ZERO_RUN_STEP = '''      - name: Execute native zero-matrix locality costs
        if: always()
        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite zero-locality
'''
ZERO_COMPARE_STEP = '''      - name: Check zero-matrix streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-zero-locality-comparison.json" --suite zero-locality
'''
ONE_ZERO_RUN_STEP = '''      - name: Execute native one-zero rank-one locality costs
        if: always()
        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite one-zero-locality
'''
ONE_ZERO_COMPARE_STEP = '''      - name: Check one-zero rank-one streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-one-zero-locality-comparison.json" --suite one-zero-locality
'''
MAINTENANCE_RUN_STEP = '''      - name: Execute native fixed maintenance paired-product costs
        if: always()
        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}" --suite maintenance-paired
'''
MAINTENANCE_COMPARE_STEP = '''      - name: Check fixed maintenance streams and exact source identity
        if: always()
        run: python3 scripts/ci/check_cross_arch_cost.py --artifacts "$RUNNER_TEMP/cost-inputs" --expected-source "$TRNM_EXPECTED_SOURCE_SHA" --output "$RUNNER_TEMP/ci-observations/cross-arch-maintenance-comparison.json" --suite maintenance-paired
'''
CONTINUITY_BUILD = '    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee --examples\n'
CONTINUITY_ORIGINAL = '    TRNM_CONTINUITY_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_vectors")" python3 formal/pon-nakamoto-v1/test_continuity.py -v\n'
CONTINUITY_TRANSITIONS = '    TRNM_CONTINUITY_TRANSITIONS_BINARY="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_transition_vectors")" python3 formal/pon-nakamoto-v1/test_continuity_transitions.py -v\n'
PAIRED_WORK_ORACLE = '    TRNM_PAIRED_WORK="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_paired_io")" TRNM_PAIRED_WORK_OUTPUT="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/paired-work" python3 formal/pon-nakamoto-v1/test_paired_work.py -v\n'
MODEL_WINDOW_ORACLE = '    python3 formal/pon-nakamoto-v1/test_model_window_history.py -v\n'
NODE_EXAMPLE_BUILD = '    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --bins --examples\n'
ACCOUNT_ARCHIVE_ORACLE = ('    python3 formal/pon-nakamoto-v1/test_account_archive_oracle.py -v\n'
                          '    python3 scripts/ci/run_account_archive_conformance.py\n')
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
      cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features
      python3 formal/pon-nakamoto-v1/test_model_composition_oracle.py -v
      python3 formal/pon-nakamoto-v1/test_model_composition.py -v
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
    continuity = CONTINUITY_BUILD + CONTINUITY_ORIGINAL + CONTINUITY_TRANSITIONS + PAIRED_WORK_ORACLE
    require(continuity in lanes['protocol-contract'] and script.count(CONTINUITY_ORIGINAL) == 1
            and script.count(CONTINUITY_TRANSITIONS) == 1,
            'continuity and paired-work oracles must execute in protocol-contract after their actual release build')
    require(script.count(PAIRED_WORK_ORACLE) == 1,
            'one native paired-work byte comparison must retain its fresh current-lane output')
    require(MODEL_WINDOW_ORACLE in lanes['protocol-contract'] and script.count(MODEL_WINDOW_ORACLE) == 1,
            'model-window history arithmetic and frozen evidence checks must execute once in protocol-contract')
    require(NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE in lanes['protocol-contract'] and
            script.count(ACCOUNT_ARCHIVE_ORACLE) == 1,
            'native archive vectors and the independent read-only oracle must execute after their actual release build')
    expected = ('    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check\n'
                '    python3 scripts/ci/run_supply_chain.py\n' + MODEL_OBSERVATION_BLOCK + RUST_DOCS + RUST_CLIPPY)
    require(code_lines(lanes['rust-baseline']) == code_lines(expected),
            'one actual workspace test must collect fresh model observations, immediately check both oracles, then run docs/Clippy outside exports')
    require(script.count(RUST_ALL_TARGETS) == 1, 'the full workspace observation suite must execute exactly once')
    for selector in ['TRNM_MODEL_COMPOSITION_VECTORS', 'TRNM_MODEL_COMPOSITION_RUN_ID']:
        require(script.count(selector) == MODEL_OBSERVATION_BLOCK.count(selector),
                'model observation selectors must remain inside the single test/oracle subshell')


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
            'architecture job must cover four bounded suites and retain their outcomes')
    require(COST_JOB_OVERHEAD_SECONDS >= 27 * 60 and
            COST_JOB_TIMEOUT_MINUTES * 60 >= cost_job_budget_seconds(),
            'all four actual capture budgets, termination grace and setup/source/artifact margin must fit')
    require('''        include:
          - arch: x64
            runner: ubuntu-24.04
          - arch: arm64
            runner: ubuntu-24.04-arm
''' in costs, 'two explicit native hosted runner architectures required')
    require('      TRNM_COST_RUNNER_LABEL: ${{ matrix.runner }}\n' in costs and
            '        run: rustup toolchain install 1.99.0 --profile minimal\n' in costs,
            'observed runner label and pinned native release compiler required')
    require('        run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}"\n' in costs,
            'architecture names are not a substitute for native cost execution')
    require(ZERO_RUN_STEP in costs and text.count(ZERO_RUN_STEP) == 1,
            'separate zero locality native execution must run once in each existing architecture job, including after reused failure')
    require(ZERO_RUN_STEP + ONE_ZERO_RUN_STEP in costs and text.count(ONE_ZERO_RUN_STEP) == 1,
            'one-zero locality must run once after the zero suite, including after either preceding suite failed')
    require(ONE_ZERO_RUN_STEP + MAINTENANCE_RUN_STEP in costs and text.count(MAINTENANCE_RUN_STEP) == 1,
            'fixed maintenance must execute once after the three retained suites including their failure paths')
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
    merge = jobs['prospective-merge']
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
    archive_negative = '    python3 scripts/ci/test_account_archive_conformance.py\n'
    require(archive_negative in dict(lane_pairs)['repository-truth'] and script.count(archive_negative) == 1,
            'archive native/oracle receipt negatives must execute once in repository-truth')
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
