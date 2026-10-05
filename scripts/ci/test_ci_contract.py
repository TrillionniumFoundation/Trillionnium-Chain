#!/usr/bin/env python3
"""Negative checks for real lane execution, merge identity, and generated navigation."""
from __future__ import annotations

import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from check_ci_contract import (ROOT, validate, CONTINUITY_BUILD, CONTINUITY_TRANSITIONS,
                               MODEL_OBSERVATION_BLOCK, RUST_ALL_TARGETS, RUST_DOCS, SIGNED_STATE_PYTHON,
                               ZERO_RUN_STEP, ZERO_COMPARE_STEP, ONE_ZERO_RUN_STEP,
                               ONE_ZERO_COMPARE_STEP, MAINTENANCE_RUN_STEP,
                               MAINTENANCE_COMPARE_STEP, PAIRED_WORK_ORACLE, MODEL_WINDOW_ORACLE,
                               NODE_EXAMPLE_BUILD, ACCOUNT_ARCHIVE_ORACLE, ACCOUNT_EXECUTION_ORACLE)
from check_cross_arch_cost import (COST_JOB_OVERHEAD_SECONDS, COST_JOB_TIMEOUT_MINUTES,
                                   cost_job_budget_seconds)
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

    def test_zero_native_execution_cannot_be_removed_skipped_or_replaced(self):
        for replacement in ['', ZERO_RUN_STEP.replace('        if: always()\n', ''),
                            ZERO_RUN_STEP.replace('run: python3', 'run: true # python3')]:
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', ZERO_RUN_STEP, replacement)

    def test_architecture_budget_covers_four_bounded_suites_and_termination_margin(self):
        self.assertEqual(cost_job_budget_seconds() - COST_JOB_OVERHEAD_SECONDS, 6480)
        self.assertGreaterEqual(COST_JOB_TIMEOUT_MINUTES * 60, cost_job_budget_seconds())
        for minutes in [30, 60, 90, 108, 120]:
            with self.subTest(minutes=minutes):
                self.rejected('.github/workflows/trnm-required-baseline.yml',
                              '    timeout-minutes: 135\n', f'    timeout-minutes: {minutes}\n')

    def test_maintenance_native_execution_cannot_be_removed_skipped_or_substituted(self):
        for replacement in ['', MAINTENANCE_RUN_STEP.replace('        if: always()\n', ''),
                            MAINTENANCE_RUN_STEP.replace('run: python3', 'run: true # python3'),
                            MAINTENANCE_RUN_STEP.replace(' --suite maintenance-paired', ' --suite one-zero-locality')]:
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', MAINTENANCE_RUN_STEP, replacement)

    def test_maintenance_comparison_cannot_be_removed_skipped_or_substituted(self):
        for replacement in ['', MAINTENANCE_COMPARE_STEP.replace('        if: always()\n', ''),
                            MAINTENANCE_COMPARE_STEP.replace('run: python3', 'run: true # python3'),
                            MAINTENANCE_COMPARE_STEP.replace(' --suite maintenance-paired', ' --suite one-zero-locality')]:
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', MAINTENANCE_COMPARE_STEP, replacement)

    def test_maintenance_execution_and_comparison_preserve_sequential_failure_collection(self):
        for first, second in [(ONE_ZERO_RUN_STEP, MAINTENANCE_RUN_STEP),
                              (ONE_ZERO_COMPARE_STEP, MAINTENANCE_COMPARE_STEP)]:
            with self.subTest(step=second):
                self.rejected('.github/workflows/trnm-required-baseline.yml', first + second, second + first)
                self.rejected('.github/workflows/trnm-required-baseline.yml', second, second + second)

    def test_maintenance_suite_cannot_move_into_the_wrong_job(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        original = (self.root / path).read_text()
        for step, destination in [(MAINTENANCE_RUN_STEP, MAINTENANCE_COMPARE_STEP),
                                  (MAINTENANCE_COMPARE_STEP, MAINTENANCE_RUN_STEP)]:
            with self.subTest(step=step):
                changed = original.replace(step, '').replace(destination, destination + step)
                self.rejected(path, original, changed)

    def test_maintenance_negative_checks_execute_once_in_repository_truth(self):
        path = 'scripts/ci/ci_job.sh'
        command = '    python3 scripts/ci/test_maintenance_cost.py\n'
        for replacement in ['', '    true # omitted maintenance checks\n', command + command]:
            with self.subTest(replacement=replacement):
                self.rejected(path, command, replacement)
        original = (self.root / path).read_text()
        changed = original.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
        self.rejected(path, original, changed)

    def test_zero_comparison_cannot_be_removed_or_replaced_by_old_suite(self):
        for replacement in ['', ZERO_COMPARE_STEP.replace(' --suite zero-locality', ''),
                            ZERO_COMPARE_STEP.replace('        if: always()\n', ''),
                            ZERO_COMPARE_STEP.replace('run: python3', 'run: true # python3')]:
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', ZERO_COMPARE_STEP, replacement)

    def test_zero_suite_cannot_move_into_the_wrong_job(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        original = (self.root / path).read_text()
        for step, destination in [(ZERO_RUN_STEP, ZERO_COMPARE_STEP), (ZERO_COMPARE_STEP, ZERO_RUN_STEP)]:
            with self.subTest(step=step):
                changed = original.replace(step, '').replace(destination, destination + step)
                self.rejected(path, original, changed)

    def test_zero_negative_checks_must_run_once_in_repository_truth(self):
        path = 'scripts/ci/ci_job.sh'
        command = '    python3 scripts/ci/test_zero_locality_cost.py\n'
        for replacement in ['', '    true # omitted zero checker tests\n', command + command]:
            with self.subTest(replacement=replacement):
                self.rejected(path, command, replacement)
        original = (self.root / path).read_text()
        changed = original.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
        self.rejected(path, original, changed)

    def test_one_zero_native_execution_cannot_be_removed_skipped_or_replaced(self):
        for replacement in ['', ONE_ZERO_RUN_STEP.replace('        if: always()\n', ''),
                            ONE_ZERO_RUN_STEP.replace('run: python3', 'run: true # python3'),
                            ONE_ZERO_RUN_STEP.replace(' --suite one-zero-locality', ' --suite zero-locality')]:
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', ONE_ZERO_RUN_STEP, replacement)

    def test_one_zero_comparison_cannot_be_removed_skipped_or_relabelled(self):
        for replacement in ['', ONE_ZERO_COMPARE_STEP.replace('        if: always()\n', ''),
                            ONE_ZERO_COMPARE_STEP.replace('run: python3', 'run: true # python3'),
                            ONE_ZERO_COMPARE_STEP.replace(' --suite one-zero-locality', ' --suite zero-locality')]:
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', ONE_ZERO_COMPARE_STEP, replacement)

    def test_one_zero_suite_cannot_move_to_the_wrong_job(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        original = (self.root / path).read_text()
        for step, destination in [(ONE_ZERO_RUN_STEP, ONE_ZERO_COMPARE_STEP),
                                  (ONE_ZERO_COMPARE_STEP, ONE_ZERO_RUN_STEP)]:
            with self.subTest(step=step):
                changed = original.replace(step, '').replace(destination, destination + step)
                self.rejected(path, original, changed)

    def test_one_zero_execution_and_comparison_keep_their_separate_sequential_steps(self):
        for first, second in [(ZERO_RUN_STEP, ONE_ZERO_RUN_STEP),
                              (ZERO_COMPARE_STEP, ONE_ZERO_COMPARE_STEP)]:
            with self.subTest(step=second):
                self.rejected('.github/workflows/trnm-required-baseline.yml', first + second, second + first)
                self.rejected('.github/workflows/trnm-required-baseline.yml', second, second + second)

    def test_one_zero_negative_checks_must_run_once_in_repository_truth(self):
        path = 'scripts/ci/ci_job.sh'
        command = '    python3 scripts/ci/test_one_zero_locality_cost.py\n'
        for replacement in ['', '    true # omitted one-zero checker tests\n', command + command]:
            with self.subTest(replacement=replacement):
                self.rejected(path, command, replacement)
        original = (self.root / path).read_text()
        changed = original.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
        self.rejected(path, original, changed)

    def test_finite_tests_cannot_replace_fuzz_invocation(self):
        self.rejected('scripts/ci/ci_job.sh', '    python3 scripts/ci/run_fuzz_smoke.py\n', '')

    def test_config_file_is_not_dependency_execution(self):
        self.rejected('scripts/ci/ci_job.sh', '    python3 scripts/ci/run_supply_chain.py\n', '')

    def test_public_campaign_must_execute_and_preserve_its_report(self):
        self.rejected('scripts/ci/ci_job.sh',
                      '    python3 scripts/run_public_v3_service_campaign.py --out ',
                      '    true # omitted campaign output ')

    def test_continuity_oracle_cannot_be_removed_or_replaced_with_true(self):
        for replacement in ['', '    true # omitted continuity transitions\n']:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', CONTINUITY_TRANSITIONS, replacement)

    def test_continuity_oracle_requires_actual_built_binary(self):
        self.rejected('scripts/ci/ci_job.sh', CONTINUITY_BUILD, '')
        self.rejected('scripts/ci/ci_job.sh', 'realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuity_transition_vectors"',
                      'printf %s /old/unverified/continuity_transition_vectors')

    def test_continuity_oracle_cannot_move_to_another_lane(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        changed = original.replace(CONTINUITY_TRANSITIONS, '').replace('  fuzz-smoke)\n',
                                                                             '  fuzz-smoke)\n' + CONTINUITY_TRANSITIONS)
        self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_paired_work_oracle_cannot_be_removed_skipped_or_reuse_historical_output(self):
        for replacement in ['', '    true # omitted paired work oracle\n',
                            PAIRED_WORK_ORACLE.replace('realpath -e', 'printf %s'),
                            PAIRED_WORK_ORACLE.replace('/paired-work"', '/old-paired-work"'),
                            PAIRED_WORK_ORACLE + PAIRED_WORK_ORACLE]:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', PAIRED_WORK_ORACLE, replacement)

    def test_paired_and_model_window_oracles_cannot_move_to_another_lane(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        for command in [PAIRED_WORK_ORACLE, MODEL_WINDOW_ORACLE]:
            changed = original.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
            with self.subTest(command=command):
                self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_model_window_history_oracle_must_execute_once(self):
        for replacement in ['', '    true # omitted model-window checks\n', MODEL_WINDOW_ORACLE * 2]:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', MODEL_WINDOW_ORACLE, replacement)

    def test_archive_oracle_requires_release_build_and_both_actual_checks(self):
        for replacement in ['', '    true # omitted native archive and oracle\n',
                            ACCOUNT_ARCHIVE_ORACLE.splitlines(keepends=True)[0],
                            ACCOUNT_ARCHIVE_ORACLE.splitlines(keepends=True)[1],
                            ACCOUNT_ARCHIVE_ORACLE * 2]:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', ACCOUNT_ARCHIVE_ORACLE, replacement)
        self.rejected('scripts/ci/ci_job.sh', NODE_EXAMPLE_BUILD, '')
        self.rejected('scripts/ci/ci_job.sh', NODE_EXAMPLE_BUILD + ACCOUNT_ARCHIVE_ORACLE,
                      ACCOUNT_ARCHIVE_ORACLE + NODE_EXAMPLE_BUILD)

    def test_archive_oracle_and_negative_checks_cannot_move_to_another_lane(self):
        path = 'scripts/ci/ci_job.sh'
        original = (self.root / path).read_text()
        for command in [ACCOUNT_ARCHIVE_ORACLE, '    python3 scripts/ci/test_account_archive_conformance.py\n']:
            changed = original.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
            with self.subTest(command=command):
                self.rejected(path, original, changed)

    def test_account_execution_oracles_require_release_build_and_all_actual_checks(self):
        for replacement in ['', '    true # omitted account execution and oracle\n',
                            *ACCOUNT_EXECUTION_ORACLE.splitlines(keepends=True),
                            ACCOUNT_EXECUTION_ORACLE * 2]:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', ACCOUNT_EXECUTION_ORACLE, replacement)
        for command in ACCOUNT_EXECUTION_ORACLE.splitlines(keepends=True):
            with self.subTest(missing=command):
                self.rejected('scripts/ci/ci_job.sh', command, '')
        self.rejected('scripts/ci/ci_job.sh', NODE_EXAMPLE_BUILD, '')
        self.rejected('scripts/ci/ci_job.sh', ACCOUNT_ARCHIVE_ORACLE + ACCOUNT_EXECUTION_ORACLE,
                      ACCOUNT_EXECUTION_ORACLE + ACCOUNT_ARCHIVE_ORACLE)

    def test_account_execution_and_receipt_controls_cannot_move_or_duplicate(self):
        path = 'scripts/ci/ci_job.sh'
        original = (self.root / path).read_text()
        command = '    python3 scripts/ci/test_run_account_execution_conformance.py\n'
        for replacement in ['', '    true # omitted execution receipt checks\n', command + command]:
            with self.subTest(replacement=replacement):
                self.rejected(path, command, replacement)
        for moved in [ACCOUNT_EXECUTION_ORACLE, command]:
            changed = original.replace(moved, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + moved)
            with self.subTest(command=moved):
                self.rejected(path, original, changed)

    def test_both_model_oracles_cannot_be_removed_or_replaced_with_true(self):
        for filename in ['test_model_composition_oracle.py', 'test_model_composition.py']:
            command = '      python3 formal/pon-nakamoto-v1/' + filename + ' -v\n'
            for replacement in ['', '      true # omitted model oracle\n']:
                with self.subTest(filename=filename, replacement=replacement):
                    self.rejected('scripts/ci/ci_job.sh', command, replacement)

    def test_model_observations_require_unique_directory_and_run_selector(self):
        for command in ['      test ! -e "$TRNM_MODEL_COMPOSITION_VECTORS"\n',
                        '      test ! -L "$TRNM_MODEL_COMPOSITION_VECTORS"\n',
                        '      export TRNM_MODEL_COMPOSITION_RUN_ID="$(python3 -c \'import secrets; print(secrets.token_hex(32))\')"\n']:
            with self.subTest(command=command):
                self.rejected('scripts/ci/ci_job.sh', command, '')

    def test_signed_state_oracle_requires_fresh_native_outputs_and_actual_checks(self):
        for command in [
                '      export TRNM_AUTHENTICATED_STATE_VECTORS="$trnm_model_receipt_root/authenticated-state/native.json"\n',
                '      test ! -e "$trnm_model_receipt_root/authenticated-state"\n',
                '      test ! -L "$trnm_model_receipt_root/authenticated-state"\n',
                '      python3 formal/pon-nakamoto-v1/test_authenticated_state_archive_oracle.py -v\n',
                '      python3 formal/pon-nakamoto-v1/authenticated_state_archive_oracle.py "$TRNM_AUTHENTICATED_STATE_VECTORS" "$trnm_model_receipt_root/authenticated-state/native.sqlite" --output "$trnm_model_receipt_root/authenticated-state/oracle.json"\n']:
            for replacement in ['', '      true # omitted signed-state observation\n']:
                with self.subTest(command=command, replacement=replacement):
                    self.rejected('scripts/ci/ci_job.sh', command, replacement)

    def test_signed_state_oracle_dependencies_are_installed_in_both_rust_lanes(self):
        workflow = '.github/workflows/trnm-required-baseline.yml'
        for replacement in ['', SIGNED_STATE_PYTHON.replace('--only-binary=:all:', '--no-deps'),
                            SIGNED_STATE_PYTHON.replace('          echo "$RUNNER_TEMP/pon-state-env/bin" >> "$GITHUB_PATH"\n', '')]:
            with self.subTest(replacement=replacement):
                self.rejected(workflow, SIGNED_STATE_PYTHON, replacement)
        self.rejected(workflow,
                      "if: matrix.lane == 'protocol-contract' || matrix.lane == 'external-evidence-contract' || matrix.lane == 'rust-baseline'",
                      "if: matrix.lane == 'protocol-contract' || matrix.lane == 'external-evidence-contract'")

    def test_model_observation_block_cannot_move_to_another_lane(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        changed = original.replace(MODEL_OBSERVATION_BLOCK, '').replace('  fuzz-smoke)\n',
                                                                              '  fuzz-smoke)\n' + MODEL_OBSERVATION_BLOCK)
        self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_model_oracles_must_precede_documentation_tests(self):
        self.rejected('scripts/ci/ci_job.sh', MODEL_OBSERVATION_BLOCK + RUST_DOCS,
                      RUST_DOCS + MODEL_OBSERVATION_BLOCK)

    def test_model_exports_cannot_leak_into_doc_or_clippy_commands(self):
        self.rejected('scripts/ci/ci_job.sh', '    )\n' + RUST_DOCS, RUST_DOCS + '    )\n')
        self.rejected('scripts/ci/ci_job.sh', '    )\n' + RUST_DOCS,
                      '    )\n    export TRNM_MODEL_COMPOSITION_VECTORS=/old/data\n' + RUST_DOCS)

    def test_workspace_test_cannot_be_replaced_skipped_or_duplicated(self):
        self.rejected('scripts/ci/ci_job.sh', '      ' + RUST_ALL_TARGETS + '\n', '      true\n')
        self.rejected('scripts/ci/ci_job.sh', '      ' + RUST_ALL_TARGETS + '\n',
                      '      if false; then\n      ' + RUST_ALL_TARGETS + '\n      fi\n')
        self.rejected('scripts/ci/ci_job.sh', RUST_DOCS, '    ' + RUST_ALL_TARGETS + '\n' + RUST_DOCS)

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
