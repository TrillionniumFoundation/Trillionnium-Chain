#!/usr/bin/env python3
"""Negative checks for real lane execution, merge identity, and generated navigation."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from check_ci_contract import (ROOT, validate, CONTINUITY_BUILD, CONTINUITY_TRANSITIONS,
                               MODEL_OBSERVATION_BLOCK, RUST_ALL_TARGETS, RUST_DOCS, SIGNED_STATE_PYTHON,
                               ZERO_RUN_STEP, ZERO_COMPARE_STEP, ONE_ZERO_RUN_STEP,
                               ONE_ZERO_COMPARE_STEP, MAINTENANCE_RUN_STEP,
                               MAINTENANCE_COMPARE_STEP, REJECTION_RUN_STEP, REJECTION_COMPARE_STEP,
                               PAIRED_WORK_ORACLE, ZERO_WORK_ORACLE, MODEL_WINDOW_ORACLE,
                               NATIVE_RELEASE_BLOCK,
                               NODE_EXAMPLE_BUILD, ACCOUNT_ARCHIVE_ORACLE, ACCOUNT_EXECUTION_ORACLE)
from check_cross_arch_cost import (COST_JOB_OVERHEAD_SECONDS, COST_JOB_TIMEOUT_MINUTES,
                                   cost_job_budget_seconds, rejection_job_budget_seconds)
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

    def test_zero_native_execution_and_comparison_require_explicit_current_version(self):
        for command in [ZERO_RUN_STEP, ZERO_COMPARE_STEP]:
            for selector in ['', ' --zero-version 1', ' --zero-version 3',
                             ' --zero-version 2 --zero-version 1']:
                with self.subTest(command=command, selector=selector):
                    self.rejected('.github/workflows/trnm-required-baseline.yml', command,
                                  command.replace(' --zero-version 2', selector))

    def test_architecture_budget_covers_generation_rejection_and_termination_margin(self):
        self.assertEqual(rejection_job_budget_seconds(), 1195)
        self.assertEqual(cost_job_budget_seconds() - COST_JOB_OVERHEAD_SECONDS, 6480 + 1195)
        self.assertGreaterEqual(COST_JOB_TIMEOUT_MINUTES * 60, cost_job_budget_seconds())
        for minutes in [30, 60, 90, 108, 120, 135, 150]:
            with self.subTest(minutes=minutes):
                self.rejected('.github/workflows/trnm-required-baseline.yml',
                              '    timeout-minutes: 155\n', f'    timeout-minutes: {minutes}\n')

    def test_complete_rust_budget_must_be_present_once_in_head(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        original = '    timeout-minutes: 90\n'
        for replacement in ['', '    timeout-minutes: 45\n', original + original]:
            with self.subTest(replacement=replacement):
                self.rejected(path, original, replacement)

    def test_merge_rust_budget_must_match_head_without_expanding_other_lanes(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        original = "    timeout-minutes: ${{ matrix.lane == 'rust-baseline' && 90 || 45 }}\n"
        for replacement in ['', '    timeout-minutes: 45\n', '    timeout-minutes: 90\n',
                            original.replace('==', '!='), original.replace('90 || 45', '45 || 90'),
                            original.replace("'rust-baseline'", "'protocol-contract'"), original + original]:
            with self.subTest(replacement=replacement):
                self.rejected(path, original, replacement)

    def test_rejection_run_and_comparison_require_actual_ordered_bound_execution(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        for previous, step in [(MAINTENANCE_RUN_STEP, REJECTION_RUN_STEP),
                               (MAINTENANCE_COMPARE_STEP, REJECTION_COMPARE_STEP)]:
            for replacement in ['', step.replace('        if: always()\n', ''),
                                step.replace('run: python3', 'run: true # python3'), step + step]:
                with self.subTest(step=step, replacement=replacement):
                    self.rejected(path, step, replacement)
            self.rejected(path, previous + step, step + previous)
        for option in ['--expected-source "$TRNM_EXPECTED_SOURCE_SHA"',
                       '--expected-run "$GITHUB_RUN_ID"', '--expected-attempt "$GITHUB_RUN_ATTEMPT"']:
            self.rejected(path, REJECTION_COMPARE_STEP, REJECTION_COMPARE_STEP.replace(' ' + option, ''))

    def test_rejection_parser_negatives_execute_once_in_repository_truth(self):
        path = 'scripts/ci/ci_job.sh'
        command = '    python3 scripts/ci/test_work_rejection_report.py\n'
        for replacement in ['', '    true # omitted rejection checks\n', command + command]:
            self.rejected(path, command, replacement)
        original = (self.root / path).read_text()
        changed = original.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
        self.rejected(path, original, changed)

    def test_rejection_comparison_output_uses_actual_job_environment(self):
        workflow = (self.root / '.github/workflows/trnm-required-baseline.yml').read_text()
        job = workflow.split('  cross-arch-cost-consistency:\n', 1)[1].split('\n  prospective-merge:', 1)[0]
        commands = [line.strip().removeprefix('run: ') for line in job.splitlines()
                    if line.strip().startswith('run: python3 scripts/pon_work_rejection_report.py --compare ')]
        self.assertEqual(len(commands), 1)
        runner = str(self.root.parent / 'actual runner temp')
        # This job gets RUNNER_TEMP from Actions; it does not initialize the
        # cost-runner-only TRNM_CI_RECEIPT_DIR. Execute real shell expansion of
        # the checked-in command without launching a collector or writing files.
        env = {'PATH': '/usr/bin:/bin', 'RUNNER_TEMP': runner,
               'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_RUN_ID': '1',
               'GITHUB_RUN_ATTEMPT': '1'}
        def expand(command):
            return subprocess.run(['bash', '-u', '-c', 'set -- ' + command + '; printf "%s\\n" "$@"'],
                                  env=env, capture_output=True, text=True, timeout=10)
        actual = expand(commands[0])
        self.assertEqual(actual.returncode, 0, actual.stderr)
        arguments = actual.stdout.splitlines()
        self.assertEqual(arguments.count('--out'), 1)
        self.assertEqual(arguments[arguments.index('--out') + 1],
                         str(Path(runner) / 'ci-observations/work-rejection-comparison'))
        self.assertIn('path: ${{ runner.temp }}/ci-observations/', job)
        broken = expand(commands[0].replace('$RUNNER_TEMP/ci-observations/work-rejection-comparison',
                                           '$TRNM_CI_RECEIPT_DIR/work-rejection-comparison'))
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn('TRNM_CI_RECEIPT_DIR', broken.stderr)

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

    def test_native_storage_migration_and_multiproof_oracles_follow_actual_workspace(self):
        path = 'scripts/ci/ci_job.sh'
        text = (self.root / path).read_text()
        lines = [line + '\n' for line in text.splitlines()
                 if line.startswith('      python3 formal/pon-nakamoto-v1/') and
                 any(name in line for name in ['native_authenticated_storage_oracle.py',
                                               'account_multiproof_oracle.py'])]
        self.assertEqual(len(lines), 5)
        for line in lines:
            for replacement in ['', line.replace('python3 ', 'true # python3 '), line + line]:
                with self.subTest(line=line, replacement=replacement):
                    self.rejected(path, line, replacement)
        for selector in ['TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR',
                         'TRNM_AUTHENTICATED_MIGRATION_EXPORT', 'TRNM_ACCOUNT_MULTIPROOF_VECTORS']:
            self.rejected(path, 'export ' + selector + '=', 'export OMITTED_' + selector + '=')
        self.rejected(path, '--migration-source "$TRNM_AUTHENTICATED_MIGRATION_EXPORT/source.sqlite" ', '')

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

    def test_zero_work_oracle_requires_current_release_binary_fresh_output_and_full_execution(self):
        for replacement in ['', '    true # omitted zero native/scalar byte comparison\n',
                            ZERO_WORK_ORACLE.replace('realpath -e', 'printf %s'),
                            ZERO_WORK_ORACLE.replace('TRNM_ZERO_WORK=', 'TRNM_PAIRED_WORK='),
                            ZERO_WORK_ORACLE.replace('TRNM_ZERO_WORK_OUTPUT=', 'OMITTED_OUTPUT='),
                            ZERO_WORK_ORACLE.replace('/zero-work"', '/prior-zero-work"'),
                            ZERO_WORK_ORACLE.replace('pon_zero_io', 'pon_paired_io'),
                            ZERO_WORK_ORACLE * 2]:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', ZERO_WORK_ORACLE, replacement)
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        changed = original.replace(ZERO_WORK_ORACLE, '').replace('  fuzz-smoke)\n',
                                                                  '  fuzz-smoke)\n' + ZERO_WORK_ORACLE)
        self.rejected('scripts/ci/ci_job.sh', original, changed)
        self.rejected('scripts/ci/ci_job.sh', PAIRED_WORK_ORACLE + ZERO_WORK_ORACLE,
                      ZERO_WORK_ORACLE + PAIRED_WORK_ORACLE)

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

    def test_obligation_export_and_both_reader_controls_are_mandatory_and_fresh(self):
        path = 'scripts/ci/ci_job.sh'
        lines = [
            '      export TRNM_OBLIGATION_RANGE_VECTORS="$trnm_model_receipt_root/obligation-range/native.json"\n',
            '      test ! -e "$trnm_model_receipt_root/obligation-range"\n',
            '      test ! -L "$trnm_model_receipt_root/obligation-range"\n',
            '      mkdir "$trnm_model_receipt_root/obligation-range"\n',
            '      python3 formal/pon-nakamoto-v1/test_obligation_range_oracle.py -v\n',
            '      python3 formal/pon-nakamoto-v1/obligation_range_oracle.py "$TRNM_OBLIGATION_RANGE_VECTORS" --output "$trnm_model_receipt_root/obligation-range/oracle.json"\n',
        ]
        for line in lines:
            for replacement in ['', '      true # omitted obligation range gate\n', line * 2]:
                with self.subTest(line=line, replacement=replacement):
                    self.rejected(path, line, replacement)
        self.rejected(path, lines[0], lines[0].replace('TRNM_OBLIGATION_RANGE_VECTORS=', 'WRONG_VECTORS='))
        self.rejected(path, lines[-1], lines[-1].replace('"$TRNM_OBLIGATION_RANGE_VECTORS"', '"/old/native.json"'))

    def test_zero_prefix_export_is_unique_to_workspace_then_independently_recomputed(self):
        path = 'scripts/ci/ci_job.sh'
        lines = [
            '      export TRNM_ZERO_PAIRED_PREFIX_OUTPUT="$trnm_model_receipt_root/zero-paired-prefix"\n',
            '      test ! -e "$TRNM_ZERO_PAIRED_PREFIX_OUTPUT"\n',
            '      test ! -L "$TRNM_ZERO_PAIRED_PREFIX_OUTPUT"\n',
            '      unset TRNM_ZERO_PAIRED_PREFIX_OUTPUT\n',
            '      python3 formal/pon-nakamoto-v1/test_zero_work.py --verify-prefix-export "$trnm_model_receipt_root/zero-paired-prefix" --output "$trnm_model_receipt_root/zero-paired-prefix-python"\n',
        ]
        for line in lines:
            for replacement in ['', '      true # omitted zero prefix gate\n', line * 2]:
                with self.subTest(line=line, replacement=replacement):
                    self.rejected(path, line, replacement)
        self.rejected(path, lines[0], lines[0].replace('TRNM_ZERO_PAIRED_PREFIX_OUTPUT=', 'WRONG_OUTPUT='))
        self.rejected(path, lines[2], lines[2] + '      mkdir "$TRNM_ZERO_PAIRED_PREFIX_OUTPUT"\n')
        self.rejected(path, lines[-1], lines[-1].replace('/zero-paired-prefix"', '/old-prefix"'))
        self.rejected(path, lines[-1], lines[-1].replace('/zero-paired-prefix-python"', '/zero-paired-prefix"'))

    def test_full_capacity_and_account_verification_execute_exact_release_tests_sequentially(self):
        path = 'scripts/ci/ci_job.sh'
        commands = [line + '\n' for line in NATIVE_RELEASE_BLOCK.splitlines() if ' cargo test ' in line]
        self.assertEqual(len(commands), 2)
        for line in commands:
            for replacement in ['', line.replace('cargo test ', 'true # cargo test '),
                                line.replace(' --release ', ' '), line.replace(' --exact ', ' '),
                                line.replace(' --ignored ', ' '), line.replace('--test-threads=1', '--test-threads=4'),
                                line.replace('2>&1 | tee ', '2>&1 || tee '), line * 2]:
                with self.subTest(line=line, replacement=replacement):
                    self.rejected(path, line, replacement)
        self.rejected(path, commands[0], commands[0].replace(
            'native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover',
            'native_authenticated_signed_growth_branches_reopen_and_compact_queries'))
        self.rejected(path, commands[1], commands[1].replace('TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY=', 'WRONG_OUTPUT='))
        self.rejected(path, commands[1], commands[1].replace('/native-account-verification-cost"', '/old-cost"'))
        swapped = NATIVE_RELEASE_BLOCK.replace(commands[0], 'RELEASE_CONTROL_PLACEHOLDER\n')
        swapped = swapped.replace(commands[1], commands[0]).replace('RELEASE_CONTROL_PLACEHOLDER\n', commands[1])
        self.rejected(path, NATIVE_RELEASE_BLOCK, swapped)
        self.rejected(path, NATIVE_RELEASE_BLOCK, NATIVE_RELEASE_BLOCK * 2)

    def test_release_control_paths_cannot_reuse_or_overwrite_prior_observations(self):
        for line in NATIVE_RELEASE_BLOCK.splitlines(keepends=True):
            if 'test ! -e ' in line or 'test ! -L ' in line:
                with self.subTest(line=line):
                    self.rejected('scripts/ci/ci_job.sh', line, '')

    def test_release_control_pipeline_keeps_actual_shell_failure_and_output(self):
        # Exercise the exact shell block using an explicitly synthetic failing
        # cargo function. This checks pipeline failure retention, not a Rust run.
        with tempfile.TemporaryDirectory(prefix='trnm-release-pipeline-') as temporary:
            for failed_case in ['capacity', 'account']:
                root = Path(temporary) / ('receipt with spaces ' + failed_case)
                harness = '''set -euo pipefail
cargo() {
  case "$*" in
    *native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover*)
      printf '%s\\n' 'synthetic capacity stdout'
      printf '%s\\n' 'synthetic capacity stderr' >&2
      if test "$TRNM_TEST_FAILURE" = capacity; then return 7; fi ;;
    *native_complete_account_verification_cost*)
      test "$TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY" = "$TRNM_CI_RECEIPT_DIR/native-account-verification-cost"
      printf '%s\\n' 'synthetic account stdout'
      printf '%s\\n' 'synthetic account stderr' >&2
      return 9 ;;
    *) return 97 ;;
  esac
}
'''
                result = subprocess.run(['bash', '-c', harness + NATIVE_RELEASE_BLOCK],
                                        env={'PATH': '/usr/bin:/bin', 'TRNM_CI_RECEIPT_DIR': str(root),
                                             'TRNM_TEST_FAILURE': failed_case},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 7 if failed_case == 'capacity' else 9, result.stderr)
                self.assertIn('synthetic capacity stdout', (root / 'native-capacity-release.log').read_text())
                self.assertIn('synthetic capacity stderr', (root / 'native-capacity-release.log').read_text())
                account = root / 'native-account-verification-cost.log'
                if failed_case == 'capacity':
                    self.assertFalse(account.exists())
                else:
                    self.assertIn('synthetic account stdout', account.read_text())
                    self.assertIn('synthetic account stderr', account.read_text())

    def test_model_observation_block_cannot_move_to_another_lane(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        changed = original.replace(MODEL_OBSERVATION_BLOCK, '').replace('  fuzz-smoke)\n',
                                                                              '  fuzz-smoke)\n' + MODEL_OBSERVATION_BLOCK)
        self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_model_oracles_must_precede_documentation_tests(self):
        self.rejected('scripts/ci/ci_job.sh', MODEL_OBSERVATION_BLOCK + NATIVE_RELEASE_BLOCK + RUST_DOCS,
                      RUST_DOCS + MODEL_OBSERVATION_BLOCK + NATIVE_RELEASE_BLOCK)

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
