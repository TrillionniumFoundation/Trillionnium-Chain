#!/usr/bin/env python3
"""Check the deliberately fixed hosted-CI structure; this does not execute its lanes."""
from __future__ import annotations

import json
import re
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = '.github/workflows/trnm-required-baseline.yml'
CHECKOUT = 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
DOWNLOAD = 'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0'


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
    require('    timeout-minutes: 30\n' in costs and '      fail-fast: false\n' in costs,
            'both bounded architecture outcomes must be retained')
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
    require('    python3 scripts/ci/run_fuzz_smoke.py\n' in script,
            'instrumented fuzz execution missing')
    require('    python3 scripts/ci/run_supply_chain.py\n' in script,
            'locked dependency checks missing')
    require('    python3 scripts/ci/test_cross_arch_cost.py\n' in script,
            'cross-architecture evidence negative checks missing')
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
