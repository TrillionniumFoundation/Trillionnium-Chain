#!/usr/bin/env python3
"""Negative checks for real lane execution, merge identity, and generated navigation."""
from __future__ import annotations

import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from check_ci_contract import ROOT, validate
from report_current_implementation import DESTINATION, markdown, projection, validate as current_validate


class CiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-ci-contract-')
        cls.root = Path(cls.temporary.name) / 'source'
        shutil.copytree(ROOT, cls.root, ignore=shutil.ignore_patterns('.git', 'target', '__pycache__', 'artifacts'))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def rejected(self, path, before, after):
        path = self.root / path
        original = path.read_text()
        self.assertIn(before, original)
        try:
            path.write_text(original.replace(before, after, 1))
            with self.assertRaises(ValueError):
                validate(self.root)
        finally:
            path.write_text(original)

    def test_current_execution_contract(self):
        self.assertEqual(validate(self.root)['merge_lanes'], 5)
        current_validate(self.root)

    def test_finite_tests_cannot_replace_fuzz_invocation(self):
        self.rejected('scripts/ci/ci_job.sh', '    python3 scripts/ci/run_fuzz_smoke.py\n', '')

    def test_config_file_is_not_dependency_execution(self):
        self.rejected('scripts/ci/ci_job.sh', '    python3 scripts/ci/run_supply_chain.py\n', '')

    def test_public_campaign_must_execute_and_preserve_its_report(self):
        self.rejected('scripts/ci/ci_job.sh',
                      '    python3 scripts/run_public_v3_service_campaign.py --out ',
                      '    true # omitted campaign output ')

    def test_merge_lane_cannot_test_head_instead(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '      TRNM_EXPECTED_SOURCE_SHA: ${{ github.sha }}',
                      '      TRNM_EXPECTED_SOURCE_SHA: ${{ github.event.pull_request.head.sha }}')

    def test_merge_lane_requires_all_actual_lanes(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      'lane: [repository-truth, protocol-contract, fuzz-smoke, rust-baseline, external-evidence-contract]',
                      'lane: [repository-truth]')

    def test_merge_identity_is_not_itself_an_execution_pass(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      'run: bash scripts/ci/ci_job.sh "${{ matrix.lane }}"',
                      'run: python3 scripts/ci/check_repository.py')

    def test_failure_cannot_be_marked_ignorable(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '  fuzz-smoke:\n', '  fuzz-smoke:\n    continue-on-error: true\n')

    def test_arm_label_cannot_be_replaced_with_an_x64_runner(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '            runner: ubuntu-24.04-arm', '            runner: ubuntu-24.04')

    def test_architecture_label_is_not_native_cost_execution(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      'run: python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}"',
                      'run: python3 scripts/ci/check_ci_contract.py')

    def test_architecture_failure_cannot_cancel_the_other_observation(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '      fail-fast: false', '      fail-fast: true')

    def test_cross_architecture_checker_requires_retained_actual_artifacts(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '          merge-multiple: false', '          merge-multiple: true')

    def test_cross_architecture_comparison_cannot_use_a_prior_attempt(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '          pattern: cost-*-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}',
                      '          pattern: cost-*')

    def test_cross_architecture_comparison_must_execute(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      'run: python3 scripts/ci/check_cross_arch_cost.py --artifacts ',
                      'run: true # omitted comparison ')

    def test_cross_architecture_negative_checks_must_execute(self):
        self.rejected('scripts/ci/ci_job.sh', '    python3 scripts/ci/test_cross_arch_cost.py\n', '')

    def test_tool_install_is_pinned(self):
        self.rejected('scripts/ci/tool-versions.env', 'TRNM_FUZZ_TOOLCHAIN=nightly-2026-10-01',
                      'TRNM_FUZZ_TOOLCHAIN=nightly')

    def test_fuzz_cannot_silently_use_newer_shared_crypto_dependencies(self):
        packages = tomllib.loads((self.root / 'tests/fuzz/Cargo.lock').read_text())['package']
        version = next(p['version'] for p in packages if p['name'] == 'ed25519-dalek')
        self.rejected('tests/fuzz/Cargo.lock',
                      f'name = "ed25519-dalek"\nversion = "{version}"',
                      'name = "ed25519-dalek"\nversion = "99.0.0"')

    def test_summary_is_derived_and_cannot_promote_a_manual_claim(self):
        path = self.root / DESTINATION
        original = path.read_text()
        try:
            path.write_text(original + '\nAll modules accepted.\n')
            with self.assertRaises(ValueError):
                current_validate(self.root)
            path.write_text(markdown(projection(self.root)))
            current_validate(self.root)
        finally:
            path.write_text(original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
