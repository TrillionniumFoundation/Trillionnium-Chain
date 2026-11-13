#!/usr/bin/env python3
"""Negative checks for real lane execution, merge identity, and generated navigation."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

from check_ci_contract import RESEARCH_EVIDENCE_CONTROLS
from check_ci_contract import (ROOT, validate, check_inline_source_pins, CONTINUITY_BUILD, CONTINUITY_TRANSITIONS,
                               MODEL_OBSERVATION_BLOCK, RUST_ALL_TARGETS, RUST_DOCS, SIGNED_STATE_PYTHON,
                               RUNTIME_RELEASE_PYTHON, MERGE_RUNTIME_RELEASE_PYTHON,
                               RUNTIME_RELEASE_COMMAND,
                               ZERO_RUN_STEP, ZERO_COMPARE_STEP, ONE_ZERO_RUN_STEP,
                               ONE_ZERO_COMPARE_STEP, MAINTENANCE_RUN_STEP,
                               MAINTENANCE_COMPARE_STEP, REJECTION_RUN_STEP, REJECTION_COMPARE_STEP,
                               PAIRED_WORK_ORACLE, ZERO_WORK_ORACLE, MODEL_WINDOW_ORACLE,
                               MANDATORY_UNITS_NATIVE, WORK_NATIVE_MODEL_COMMANDS,
                               WORK_LIFECYCLE_NATIVE, NATIVE_OWNER_SCORE_BRIDGE,
                               LIFECYCLE_QUERY_NATIVE, NATIVE_OWNER_JOURNAL, CERTIFICATE_COMPOSITION_TESTS, NATIVE_RISK_LEDGER,
                               CREDIT_MODEL_COMMANDS, CREDIT_MODEL_PREFIX,
                               EVALUATION_QUORUM_ORACLE, check_independent_conformance,
                               check_from_zero_host_callsites,
                               MODEL_EVOLUTION_ORACLES, COST_BOUNDARY_READERS,
                               ORIGINAL_CAMPAIGN_READER,
                               NATIVE_RELEASE_BLOCK, NATIVE_GROWTH_RELEASE_BLOCK, NATIVE_GROWTH_V2_RELEASE_BLOCK,
                               GSC2_SYNTHETIC_ORACLE,
                               NODE_EXAMPLE_BUILD, NODE_POST_BUILD_CONTROLS, ACCOUNT_ARCHIVE_ORACLE, ACCOUNT_EXECUTION_ORACLE)
from check_ci_contract import (check_pq_release_authority_controls, PQ_RELEASE_WORKFLOW,
                               PQ_RELEASE_MANIFEST, PQ_RELEASE_GROUPS, PQ_ROOT_HARNESS_FILES)
from check_ci_contract import (check_pq_system_required_controls, PQ_SYSTEM_REQUIRED_MANIFEST,
                               PQ_SYSTEM_SUPPLEMENTAL_MANIFEST, PQ_SYSTEM_REQUIRED_STEP,
                               PQ_SYSTEM_SUPPLEMENTAL_STEP, PQ_CHECKPOINT_OWNERSHIP_STEP)
from check_cross_arch_cost import (COST_JOB_OVERHEAD_SECONDS, COST_JOB_TIMEOUT_MINUTES,
                                   cost_job_budget_seconds, rejection_job_budget_seconds)
from report_current_implementation import DESTINATION, markdown, projection, validate as current_validate


# Independent command inventory, not imported from the checker's expectation.
PQ_MIGRATION_TEST_COMMANDS = (
    "    PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover "
    "-s formal/pon-nakamoto-v1 -p 'test_pq_account_migration.py' -v\n",
    "    PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover "
    "-s formal/pon-nakamoto-v1 -p 'test_pq_migration_journal_owner.py' -v\n",
    "    python3 -m unittest discover -s formal/pon-nakamoto-v1 "
    "-p 'test_pq_seed_relation_vectors_v1.py' -v\n",
)


SYNTHETIC_GROWTH_PIPELINE = r'''python3() {
  if test "${1:-}" = -B && test "${2:-}" = formal/pon-nakamoto-v1/check_gsc2_native_readback.py; then
    test "$#" = 8
    test "$3" = --artifact-dir
    test "$4" = "$TRNM_CI_RECEIPT_DIR/native-growth-reference"
    test "$5" = --source-root
    test "$6" = "$(pwd -P)"
    test "$7" = --minimum-accounts
    test "$8" = 65537
    printf '%s\n' '{"scope":"synthetic shell control only, not a SQLite or native-growth observation"}'
    return "${TRNM_TEST_READBACK_STATUS:-0}"
  fi
  command python3 "$@"
}
synthetic_growth_native() {
  test "$TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY" = "$TRNM_CI_RECEIPT_DIR/native-growth-reference"
  mkdir "$TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY"
  printf '%s\n' 'running 1 test' 'test store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen ... ok' 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s'
}
synthetic_growth_v2_native() {
  test "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR" = "$TRNM_CI_RECEIPT_DIR/native-growth-v2"
  mkdir "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR"
  printf '%s\n' '{"scope":"synthetic shell control only, not a native growth observation"}' > "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR/native.json"
  printf '%s\n' 'running 1 test' 'test store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen ... ok' 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s'
}
'''


class InlineSourcePinTests(unittest.TestCase):
    def test_actual_workflow_guards_bind_current_bytes(self):
        self.assertGreater(check_inline_source_pins(ROOT), 0)

    def test_stale_missing_and_bypassed_literal_guards_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='trnm-inline-source-') as directory:
            root = Path(directory)
            (root / '.github/workflows').mkdir(parents=True)
            source = root / 'source.rs'
            raw = b'const WORK: bool = true;\n'
            source.write_bytes(raw)
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw,
                                usedforsecurity=False).hexdigest()
            guard = f'          test "$(git hash-object source.rs)" = {blob}\n'
            workflow = root / '.github/workflows/control.yml'
            workflow.write_text(guard)
            self.assertEqual(check_inline_source_pins(root), 1)
            source.write_bytes(raw.replace(b'true', b'TRUE'))
            with self.assertRaisesRegex(ValueError, 'inline source pin differs'):
                check_inline_source_pins(root)
            source.unlink()
            with self.assertRaisesRegex(ValueError, 'missing regular inline source'):
                check_inline_source_pins(root)
            source.write_bytes(raw)
            workflow.write_text(guard.rstrip() + ' || true\n')
            with self.assertRaisesRegex(ValueError, 'unsupported inline source guard'):
                check_inline_source_pins(root)

    def test_recent_log_inventory_retains_absence_and_source_failure(self):
        text = (ROOT / '.github/workflows/pon-recent-batch-acceptance.yml').read_text()
        section = text.split('      - name: Recheck unchanged exact source and hash all native logs\n', 1)[1]
        self.assertTrue(section.startswith('        if: always()\n'))
        script = section.split('        run: |\n', 1)[1].split('\n      - ', 1)[0]
        script = '\n'.join(line[10:] for line in script.splitlines()) + '\n'
        for source_status, logs in ((0, {}), (0, {'first.log': b'actual bytes\n',
                                              'with space.log': b'failed native attempt\n'}),
                                    (7, {}), (7, {'failed.log': b'failure retained\n'})):
            with self.subTest(source_status=source_status, logs=list(logs)), \
                    tempfile.TemporaryDirectory(prefix='trnm-recent-log-test-') as directory:
                output = Path(directory) / 'retained'
                output.mkdir()
                for name, data in logs.items():
                    (output / name).write_bytes(data)
                # Only the source verifier is substituted. The actual workflow
                # shell handles no logs, real file bytes and a failed verifier.
                prefix = 'python3() { return ' + str(source_status) + '; }\n'
                env = dict(os.environ, OUT=str(output), SOURCE_KIND='head',
                           EXPECTED_HEAD='1' * 40)
                result = subprocess.run(['bash', '-c', prefix + script], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, source_status, result.stderr)
                inventory = json.loads((output / 'log-inventory.json').read_text())
                self.assertEqual(inventory['retained_log_files'], len(logs))
                self.assertEqual(inventory['source_identity_exit_code'], source_status)
                self.assertEqual(inventory['status'], 'logs-retained' if logs else 'no-logs-retained')
                self.assertFalse(inventory['native_execution_established_by_inventory'])
                self.assertEqual(inventory['qualification'], 'unknown')
                checksums = (output / 'logs.sha256').read_text().splitlines()
                self.assertEqual(len(checksums), len(logs))
                for name, data in logs.items():
                    self.assertIn(hashlib.sha256(data).hexdigest() + '  ' + str(output / name), checksums)
                self.assertTrue((output / 'SCOPE.txt').is_file())


class NativeConsensusOracleLaneTests(unittest.TestCase):
    def setUp(self):
        self.script = (ROOT / 'scripts/ci/ci_job.sh').read_text()
        self.lanes = {'repository-truth', 'protocol-contract', 'fuzz-smoke',
                      'rust-baseline', 'external-evidence-contract'}

    def test_native_domain_and_historical_oracles_both_execute(self):
        check_independent_conformance(self.script, self.lanes)

    def test_native_domain_oracle_cannot_be_omitted_skipped_or_swallowed(self):
        command = '    python3 formal/pon-nakamoto-v1/test_native_consensus_reference_v1.py\n'
        for replacement in ('', '    true\n', command * 2,
                            '    if false; then\n' + command + '    fi\n',
                            command.rstrip() + ' || true\n',
                            command.rstrip() + ' &\n',
                            command.replace('test_native_', 'test_missing_')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(command, replacement), self.lanes)


class EvaluationQuorumLaneTests(unittest.TestCase):
    """Check the real lane without copying unrelated retained evidence."""

    def setUp(self):
        self.script = (ROOT / 'scripts/ci/ci_job.sh').read_text()
        self.lanes = {'repository-truth', 'protocol-contract', 'fuzz-smoke',
                      'rust-baseline', 'external-evidence-contract'}

    def test_control_domain_readers_cannot_be_omitted_duplicated_or_bypassed(self):
        for command in RESEARCH_EVIDENCE_CONTROLS.splitlines(keepends=True):
            for replacement in ('', command * 2,
                                '    if false; then\n' + command + '    fi\n',
                                '    true # ' + command.lstrip(),
                                command.rstrip() + ' || true\n',
                                command.replace('-v', '-k no_such_case -v')):
                with self.subTest(command=command, replacement=replacement):
                    with self.assertRaises(ValueError):
                        check_independent_conformance(self.script.replace(command, replacement), self.lanes)

    def test_control_domain_readers_cannot_move_to_a_different_lane(self):
        changed = self.script.replace(RESEARCH_EVIDENCE_CONTROLS, '')
        changed = changed.replace('  repository-truth)\n',
                                  '  repository-truth)\n' + RESEARCH_EVIDENCE_CONTROLS)
        with self.assertRaises(ValueError):
            check_independent_conformance(changed, self.lanes)

    def test_actual_control_commands_fail_when_the_test_file_is_missing(self):
        with tempfile.TemporaryDirectory(prefix='trnm-control-command-') as directory:
            for command in RESEARCH_EVIDENCE_CONTROLS.splitlines():
                result = subprocess.run(command.split(), cwd=directory,
                                        capture_output=True, text=True)
                with self.subTest(command=command):
                    self.assertNotEqual(result.returncode, 0)

    def test_actual_lane_preserves_quorum_reference_and_retained_vector_checks(self):
        check_independent_conformance(self.script, self.lanes)

    def test_pq_migration_commands_cannot_be_removed_skipped_repointed_or_moved(self):
        for command in PQ_MIGRATION_TEST_COMMANDS:
            self.assertEqual(self.script.count(command), 1)
            variants = {
                'removed': self.script.replace(command, ''),
                'stubbed': self.script.replace(command, '    true # omitted migration test\n'),
                'duplicated': self.script.replace(command, command * 2),
                'skipped': self.script.replace(
                    command, '    if false; then\n' + command + '    fi\n'),
                'conditional': self.script.replace(
                    command, '    if\n' + command + '    then :; fi\n'),
                'swallowed': self.script.replace(command, command.rstrip() + ' || true\n'),
                'backgrounded': self.script.replace(command, command.rstrip() + ' &\n'),
                'unmatched test selector': self.script.replace(
                    command, command.replace('test_pq_', 'test_unmatched_pq_')),
                'moved to repository-truth': self.script.replace(command, '').replace(
                    '  repository-truth)\n', '  repository-truth)\n' + command),
                'duplicated in repository-truth': self.script.replace(
                    '  repository-truth)\n', '  repository-truth)\n' + command),
            }
            if 'PYTHONWARNINGS=' in command:
                variants['removed warning policy'] = self.script.replace(
                    command, command.replace('PYTHONWARNINGS=error::ResourceWarning ', ''))
                variants['ignored resource warnings'] = self.script.replace(
                    command, command.replace('error::ResourceWarning', 'ignore::ResourceWarning'))
            for label, changed in variants.items():
                with self.subTest(command=command.strip(), change=label), self.assertRaisesRegex(
                    ValueError, 'offline migration and seed relation controls',
                ):
                    check_independent_conformance(changed, self.lanes)

    def test_pq_migration_prefix_preserves_the_original_ordered_from_zero_callsite(self):
        block = ''.join(PQ_MIGRATION_TEST_COMMANDS)
        host = ('    python3 scripts/ci/run_from_zero_host.py -- '
                'python3 scripts/ci/run_from_zero_native.py --out '
                '"${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/from-zero-native"\n')
        self.assertEqual(self.script.count(block), 1)
        self.assertEqual(self.script.count(host), 1)
        variants = {
            'swapped migration checks': self.script.replace(
                block, PQ_MIGRATION_TEST_COMMANDS[1] + PQ_MIGRATION_TEST_COMMANDS[0]
                + PQ_MIGRATION_TEST_COMMANDS[2]),
            'migration checks after native call': self.script.replace(block, '').replace(
                host, host + block),
            'missing fixed Host parent': self.script.replace(
                host, host.replace('python3 scripts/ci/run_from_zero_host.py -- ', '')),
            'changed native output': self.script.replace(
                host, host.replace('/from-zero-native"', '/other-native"')),
        }
        with tempfile.TemporaryDirectory(prefix='trnm-pq-ci-callsite-') as directory:
            root = Path(directory)
            for relative in ('.github/workflows/trnm-required-baseline.yml',
                             '.github/workflows/pon-priority-acceptance.yml',
                             '.github/workflows/pon-w1-work-security.yml'):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text((ROOT / relative).read_text())
            path = root / 'scripts/ci/ci_job.sh'
            path.parent.mkdir(parents=True)
            path.write_text(self.script)
            check_from_zero_host_callsites(root)
            for label, changed in variants.items():
                with self.subTest(change=label):
                    with self.assertRaises(ValueError):
                        check_independent_conformance(changed, self.lanes)
                    path.write_text(changed)
                    with self.assertRaisesRegex(ValueError, 'unchanged from-zero argv'):
                        check_from_zero_host_callsites(root)

    def test_pq_migration_commands_keep_actual_shell_failure_propagation(self):
        # Only this harmless synthetic shell function executes; no cryptography
        # test, native service, provider installation or ledger is invoked here.
        prelude = ('set -euo pipefail\nunset PYTHONWARNINGS\n'
                   'python3() { printf "synthetic migration test called %s\\n" '
                   '"${PYTHONWARNINGS-unset}"; return 23; }\n')
        for command in PQ_MIGRATION_TEST_COMMANDS:
            with self.subTest(command=command.strip()):
                result = subprocess.run(
                    ['bash', '-c', prelude + command + 'printf "synthetic lane continued\\n"\n'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 23, result.stderr)
                warnings = 'error::ResourceWarning' if 'PYTHONWARNINGS=' in command else 'unset'
                self.assertEqual(result.stdout, f'synthetic migration test called {warnings}\n')

    def test_fresh_work_theory_and_native_admission_controls_are_additive_and_mandatory(self):
        theory = "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fresh_work_query_floor_v0.py' -v\n"
        native = ' --test grouped_fresh_admission_v0'
        self.assertEqual(self.script.count(theory), 1)
        self.assertEqual(self.script.count(native), 1)
        for changed in (self.script.replace(theory, ''), self.script.replace(theory, theory * 2),
                        self.script.replace(theory, theory.rstrip() + ' || true\n'),
                        self.script.replace(native, ''),
                        self.script.replace(native, ' --test grouped_fresh_admission_v0 -- --ignored')):
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                check_independent_conformance(changed, self.lanes)

    def test_resource_transfer_and_shared_authority_controls_cannot_be_omitted_or_swallowed(self):
        theory = "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fresh_work_resource_transfer_v0.py' -v\n"
        native = ' --test grouped_verification_authority_v0'
        self.assertEqual(self.script.count(theory), 1)
        self.assertEqual(self.script.count(native), 1)
        variants = (self.script.replace(theory, ''),
                    self.script.replace(theory, theory * 2),
                    self.script.replace(theory, theory.rstrip() + ' || true\n'),
                    self.script.replace(theory, '    if false; then\n' + theory + '    fi\n'),
                    self.script.replace(native, ''),
                    self.script.replace(native, native + ' -- --ignored'))
        for changed in variants:
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                check_independent_conformance(changed, self.lanes)

    def test_credit_model_commands_cannot_be_omitted_duplicated_or_moved(self):
        for command in CREDIT_MODEL_COMMANDS:
            line = '    ' + command + '\n'
            variants = [self.script.replace(line, ''),
                        self.script.replace(line, '    true # omitted credit model\n'),
                        self.script.replace(line, line * 2),
                        self.script.replace(line, '').replace('  protocol-contract)\n',
                                                              '  protocol-contract)\n' + line)]
            for script in variants:
                with self.subTest(command=command, script=script), self.assertRaises(ValueError):
                    check_independent_conformance(script, self.lanes)

    def test_credit_model_commands_cannot_be_skipped_by_false_shell_branch(self):
        for command in CREDIT_MODEL_COMMANDS:
            line = '    ' + command + '\n'
            skipped = '    if false; then\n' + line + '    fi\n'
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, 'credit model prefix'):
                    check_independent_conformance(self.script.replace(line, skipped), self.lanes)
                # This reproduces the shell failure mode without executing any
                # actual model/native command or changing the source checkout.
                prelude = 'set -euo pipefail\npython3() { return 19; }\n'
                normal = subprocess.run(['bash', '-c', prelude + line],
                                        capture_output=True, text=True, timeout=5)
                bypass = subprocess.run(['bash', '-c', prelude + skipped],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(normal.returncode, 19, normal.stderr)
                self.assertEqual(bypass.returncode, 0, bypass.stderr)

    def test_credit_model_failures_cannot_be_swallowed_by_shell_condition(self):
        for command in CREDIT_MODEL_COMMANDS:
            line = '    ' + command + '\n'
            conditional = '    if\n' + line + '    then\n      :\n    fi\n'
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, 'credit model prefix'):
                    check_independent_conformance(self.script.replace(line, conditional), self.lanes)
                prelude = 'set -euo pipefail\npython3() { return 19; }\n'
                normal = subprocess.run(['bash', '-c', prelude + line],
                                        capture_output=True, text=True, timeout=5)
                bypass = subprocess.run(['bash', '-c', prelude + conditional],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(normal.returncode, 19, normal.stderr)
                self.assertEqual(bypass.returncode, 0, bypass.stderr)

    def test_entire_credit_model_prefix_cannot_be_wrapped_or_preceded(self):
        self.assertIn(CREDIT_MODEL_PREFIX, self.script)
        for replacement in ('    if false; then\n' + CREDIT_MODEL_PREFIX + '    fi\n',
                            '    if\n' + CREDIT_MODEL_PREFIX + '    then\n      :\n    fi\n',
                            '    :\n' + CREDIT_MODEL_PREFIX):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(ValueError, 'credit model prefix'):
                    check_independent_conformance(
                        self.script.replace(CREDIT_MODEL_PREFIX, replacement), self.lanes)
    def test_native_v3_and_dependency_commands_cannot_disappear_or_skip(self):
        for file in ('run_pq_root_native_v3.py', 'test_run_pq_root_native_v3.py',
                     'test_pq_root_dependency_register.py', 'pq_root_dependency_register.py',
                     'run_pq_root_continuation_v4.py', 'test_run_pq_root_continuation_v4.py',
                     'run_pq_root_witness_v5.py', 'test_run_pq_root_witness_v5.py',
                     'test_ci_observation_process.py',
                     'test_authenticated_suite_count.py',
                     'test_pq_root_custody_review_v1.py', 'pq_root_custody_review_v1.py',
                     'test_pq_root_custody_review_v2.py', 'pq_root_custody_review_v2.py',
                     'test_pq_root_migration_review_v1.py', 'pq_root_migration_review_v1.py'):
            command = '    python3 scripts/ci/' + file + '\n'
            self.assertEqual(self.script.count(command), 1)
            changes = ('', command * 2, '    true # ' + command.lstrip(),
                       command.rstrip() + ' || true\n',
                       '    if false; then\n' + command + '    fi\n')
            for changed in changes:
                with self.subTest(file=file, changed=changed), self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(command, changed), self.lanes)

    def test_custody_v2_reviewers_cannot_move_to_another_lane_or_run_in_background(self):
        for file in ('test_pq_root_custody_review_v2.py', 'pq_root_custody_review_v2.py'):
            command = '    python3 scripts/ci/' + file + '\n'
            for lane in ('protocol-contract', 'external-evidence-contract'):
                changed = self.script.replace(command, '').replace(
                    '  ' + lane + ')\n', '  ' + lane + ')\n' + command)
                with self.subTest(file=file, lane=lane), self.assertRaises(ValueError):
                    check_independent_conformance(changed, self.lanes)
            backgrounded = self.script.replace(command, command.rstrip() + ' &\n')
            with self.subTest(file=file, backgrounded=True), self.assertRaises(ValueError):
                check_independent_conformance(backgrounded, self.lanes)

    def test_root_recovery_suites_cannot_disappear_move_or_swallow_failures(self):
        # Independent filenames: deleting an entry from the checker must not
        # delete the negative coverage for that required suite.
        suites = (
            'test_pq_root_recovery_signatures_v2.py',
            'test_pq_root_effect_readback_v2.py',
            'test_pq_root_recovery_signatures_native_v2.py',
            'test_pq_root_effect_readback_native_v2.py',
            'test_pq_root_recovery_journal_native_v2.py',
        )
        for suite in suites:
            command = '    python3 formal/pon-nakamoto-v1/' + suite + ' -v\n'
            self.assertEqual(self.script.count(command), 1)
            changes = {
                'missing': self.script.replace(command, ''),
                'duplicate': self.script.replace(command, command * 2),
                'comment': self.script.replace(command, '    # ' + command.lstrip()),
                'stub': self.script.replace(command, '    true # ' + command.lstrip()),
                'conditional skip': self.script.replace(command, '    if false; then\n' + command + '    fi\n'),
                'early success': self.script.replace(command, '    exit 0\n' + command),
                'swallowed failure': self.script.replace(command, command.rstrip() + ' || true\n'),
                'wrong lane': self.script.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
                'zero-match discovery': self.script.replace(command,
                    "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'missing_" + suite + "' -v\n"),
            }
            for change, candidate in changes.items():
                with self.subTest(suite=suite, change=change), self.assertRaises(ValueError):
                    check_independent_conformance(candidate, self.lanes)

        native_block = ''.join('    python3 formal/pon-nakamoto-v1/' + suite + ' -v\n'
                               for suite in suites[2:])
        native_block += '    python3 scripts/ci/run_pq_root_native_v3.py\n'
        native_block += '    python3 scripts/ci/run_pq_root_continuation_v4.py\n'
        native_block += '    python3 scripts/ci/run_pq_root_witness_v5.py\n'
        host = ('    python3 scripts/ci/run_from_zero_host.py -- '
                'python3 scripts/ci/run_from_zero_native.py --out '
                '"${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/from-zero-native"\n')
        self.assertIn(native_block + host, self.script)
        changes = {
            'native after Host': self.script.replace(native_block + host, host + native_block),
            'Host missing': self.script.replace(host, ''),
            'Host wrapper removed': self.script.replace(host, host.replace('scripts/ci/run_from_zero_host.py -- python3 ', '')),
            'Host failure swallowed': self.script.replace(host, host.rstrip() + ' || true\n'),
            'Host skipped': self.script.replace(host, '    if false; then\n' + host + '    fi\n'),
            'success before Host': self.script.replace(host, '    exit 0\n' + host),
        }
        for change, candidate in changes.items():
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_independent_conformance(candidate, self.lanes)

    def test_cell_host_native_handoff_cannot_skip_build_or_use_an_unbound_binary(self):
        commands = (
            '    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --bin trnm-cell\n',
            '    trnm_cell_handoff_binary="$(realpath -e "${CARGO_TARGET_DIR:-trillionnium/target}/release/trnm-cell")"\n',
            '    test -x "$trnm_cell_handoff_binary"\n',
            '    TRNM_CELL_BIN="$trnm_cell_handoff_binary" python3 scripts/ci/test_llm_cell_host_handoff.py -v\n',
        )
        for command in commands:
            self.assertEqual(self.script.count(command), 1)
            for replacement in ('', command * 2, '    if false; then\n' + command + '    fi\n',
                                '    true # ' + command.lstrip(), command.rstrip() + ' || true\n'):
                with self.subTest(command=command, replacement=replacement):
                    with self.assertRaises(ValueError):
                        check_independent_conformance(self.script.replace(command, replacement), self.lanes)
        unbound = self.script.replace('TRNM_CELL_BIN="$trnm_cell_handoff_binary" ', '')
        with self.assertRaises(ValueError):
            check_independent_conformance(unbound, self.lanes)

    def test_current_readers_and_runtime_controls_cannot_be_missing_duplicated_stubbed_or_moved(self):
        # Independent inventory: removing a required command from the checker
        # must not silently remove that command's negative coverage as well.
        paths = (
            'scripts/ci/test_pon_w1_cost_matrix_reader.py',
            'scripts/ci/test_read_validated_business_goodput.py',
            'scripts/ci/test_pon_w1_reused_cost_reader_v3.py',
            'scripts/ci/test_run_w1_reused_cost_v3.py',
            'scripts/ci/test_w1_lifecycle_cost_v4.py',
            'scripts/ci/test_pon_public_v3_policy_read.py',
            'scripts/ci/test_llm_cell_handoff_deadline.py',
            'scripts/ci/test_fixed_host_service_readback_v1.py',
            'scripts/ci/test_llm_cell_installed_host.py RecoveryHandoffTests -v',
            'scripts/test_llm_runtime_trial_ledger.py',
            'scripts/test_llm_runtime_rss_owner.py',
            'scripts/test_llm_runtime_exit_observation.py',
            'scripts/test_llm_runtime_exit_subset_observation.py',
            'scripts/test_llm_runtime_exit_worker_observation.py',
            'scripts/test_llm_runtime_exit_mm_observation.py',
            'scripts/test_llm_runtime_stop.py',
            'scripts/test_llm_inherited_runtime.py',
            'scripts/test_llm_inherited_operation.py',
            'scripts/test_llm_frozen_evaluation.py',
            'scripts/test_run_learning_service_development.py',
            'scripts/test_llm_neural_read_worker.py',
            'scripts/test_llm_python_runtime_contract.py',
        )
        for path in paths:
            command = '    python3 ' + path + '\n'
            self.assertEqual(self.script.count(command), 1)
            changes = {
                'missing': self.script.replace(command, ''),
                'duplicate': self.script.replace(command, command * 2),
                'true stub': self.script.replace(command, command.replace('python3 ', 'true # python3 ')),
                'comment': self.script.replace(command, '    # ' + command.lstrip()),
                'wrong lane': self.script.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
                'other-lane duplicate': self.script.replace('  fuzz-smoke)\n', '  fuzz-smoke)\n  ' + command.lstrip()),
            }
            for label, changed in changes.items():
                with self.subTest(path=path, change=label), self.assertRaises(ValueError):
                    check_independent_conformance(changed, self.lanes)

    def test_learning_service_owner_controls_cannot_be_removed_or_swallowed(self):
        # Keep the new owner's real native execution mandatory alongside the
        # retained Task contracts, independently of the checker's constant.
        command = ('    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml '
                   '-p trnm-pon-node --example learning_service_round --example learning_service_recovery_probe --all-features '
                   '-- --test-threads=1\n')
        self.assertEqual(self.script.count(command), 1)
        changes = {
            'missing': self.script.replace(command, ''),
            'duplicate': self.script.replace(command, command * 2),
            'true stub': self.script.replace(command, '    true # ' + command.lstrip()),
            'comment': self.script.replace(command, '    # ' + command.lstrip()),
            'swallowed failure': self.script.replace(command, command.rstrip() + ' || true\n'),
            'wrong lane': self.script.replace(command, '').replace(
                '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
            'other-lane duplicate': self.script.replace(
                '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command,
            ),
            'offline removed': self.script.replace(command, command.replace(' --offline', '')),
            'lock removed': self.script.replace(command, command.replace(' --locked', '')),
            'tests skipped': self.script.replace(command, command.replace('-- --test-threads=1', '-- --ignored')),
        }
        for label, changed in changes.items():
            with self.subTest(change=label), self.assertRaisesRegex(
                    ValueError, 'native learning service reconciliation'):
                check_independent_conformance(changed, self.lanes)

    def test_proof_latency_controls_cannot_be_missing_duplicated_stubbed_or_moved(self):
        # Keep this inventory independent of the checker's command tuple.
        for name in ('test_pon_proof_latency.py', 'test_w1_proof_latency_readback.py'):
            command = '    python3 scripts/ci/' + name + '\n'
            self.assertEqual(self.script.count(command), 1)
            changes = {
                'missing': self.script.replace(command, ''),
                'duplicate': self.script.replace(command, command * 2),
                'true stub': self.script.replace(command, '    true # ' + command.lstrip()),
                'comment': self.script.replace(command, '    # ' + command.lstrip()),
                'swallowed failure': self.script.replace(command, command.rstrip() + ' || true\n'),
                'wrong lane': self.script.replace(command, '').replace(
                    '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
                'other-lane duplicate': self.script.replace(
                    '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
            }
            for label, changed in changes.items():
                with self.subTest(reader=name, change=label), self.assertRaisesRegex(
                        ValueError, 'proof latency controls'):
                    check_independent_conformance(changed, self.lanes)

    def test_current_runtime_controls_must_follow_pilot_and_parent_material(self):
        parent = '    python3 scripts/test_llm_parent_material.py\n'
        for path in ('scripts/test_llm_runtime_rss_owner.py',
                     'scripts/test_llm_runtime_exit_observation.py',
                     'scripts/test_llm_runtime_exit_subset_observation.py',
                     'scripts/test_llm_runtime_exit_worker_observation.py',
                     'scripts/test_llm_runtime_exit_mm_observation.py',
                     'scripts/test_llm_runtime_stop.py',
                     'scripts/test_llm_inherited_runtime.py',
                     'scripts/test_llm_neural_read_worker.py',
                     'scripts/test_llm_python_runtime_contract.py'):
            command = '    python3 ' + path + '\n'
            early = self.script.replace(command, '').replace(parent, command + parent)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'runtime owner'):
                check_independent_conformance(early, self.lanes)

    def test_current_runtime_controls_cannot_split_parent_material_and_parent_step(self):
        parent_step = '    python3 scripts/test_llm_runtime_parent_step.py\n'
        for path in ('scripts/test_llm_runtime_rss_owner.py',
                     'scripts/test_llm_runtime_exit_observation.py',
                     'scripts/test_llm_runtime_exit_subset_observation.py',
                     'scripts/test_llm_runtime_exit_worker_observation.py',
                     'scripts/test_llm_runtime_exit_mm_observation.py',
                     'scripts/test_llm_runtime_stop.py',
                     'scripts/test_llm_inherited_runtime.py',
                     'scripts/test_llm_neural_read_worker.py',
                     'scripts/test_llm_python_runtime_contract.py'):
            command = '    python3 ' + path + '\n'
            early = self.script.replace(command, '').replace(parent_step, command + parent_step)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'runtime owner'):
                check_independent_conformance(early, self.lanes)

    def test_gsc2_synthetic_reader_cannot_be_removed_duplicated_commented_or_moved(self):
        for replacement in ['', GSC2_SYNTHETIC_ORACLE * 2,
                            '    # ' + GSC2_SYNTHETIC_ORACLE.lstrip(),
                            GSC2_SYNTHETIC_ORACLE.replace('python3 ', 'true # python3 '),
                            GSC2_SYNTHETIC_ORACLE.replace('$(pwd -P)', '/tmp/stale-source'),
                            GSC2_SYNTHETIC_ORACLE.replace(' --source-root "$(pwd -P)"', '')]:
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, 'GSC2 synthetic'):
                check_independent_conformance(self.script.replace(GSC2_SYNTHETIC_ORACLE, replacement), self.lanes)
        moved = self.script.replace(GSC2_SYNTHETIC_ORACLE, '').replace(
            '  repository-truth)\n', '  repository-truth)\n' + GSC2_SYNTHETIC_ORACLE)
        with self.assertRaisesRegex(ValueError, 'GSC2 synthetic'):
            check_independent_conformance(moved, self.lanes)
        early = self.script.replace(GSC2_SYNTHETIC_ORACLE, '').replace(
            NODE_EXAMPLE_BUILD, GSC2_SYNTHETIC_ORACLE + NODE_EXAMPLE_BUILD)
        with self.assertRaisesRegex(ValueError, 'GSC2 synthetic'):
            check_independent_conformance(early, self.lanes)

    def test_native_growth_every_guard_and_command_is_mandatory_once_and_in_rust_lane(self):
        for command in NATIVE_GROWTH_RELEASE_BLOCK.splitlines(keepends=True):
            for replacement in ['', command * 2, '      # ' + command.lstrip(),
                                command.replace(command.lstrip(), 'true # ' + command.lstrip())]:
                with self.subTest(command=command, replacement=replacement), self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(command, replacement), self.lanes)
            moved = self.script.replace(command, '').replace('  protocol-contract)\n',
                '  protocol-contract)\n' + command)
            with self.subTest(command=command, mutation='moved'), self.assertRaises(ValueError):
                check_independent_conformance(moved, self.lanes)

    def test_native_growth_cannot_lower_threshold_relabel_test_or_reuse_export(self):
        changes = [('--minimum-accounts 65537', '--minimum-accounts 65536'),
                   ('--minimum-accounts 65537', '--minimum-accounts 64'),
                   ('--minimum-accounts 65537', ''),
                   ('native_growth_reference_65537_signed_accounts_and_cold_reopen',
                    'native_growth_reference_64_signed_accounts_and_cold_reopen'),
                   ('TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY=', 'WRONG_GROWTH_EXPORT='),
                   ('/native-growth-reference"', '/previous-growth-reference"'),
                   ('/native-growth-reference-release.log"', '/previous-growth.log"'),
                   ('--source-root "$(pwd -P)"', '--source-root /tmp/stale-source'),
                   (' --offline ', ' '), (' --locked ', ' '), (' --nocapture ', ' '),
                   (' -p trnm-pon-node ', ' -p trnm-protocol '),
                   ('2>&1 | tee ', '2>&1 || tee ')]
        for before, after in changes:
            changed = NATIVE_GROWTH_RELEASE_BLOCK.replace(before, after)
            self.assertNotEqual(changed, NATIVE_GROWTH_RELEASE_BLOCK)
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(NATIVE_GROWTH_RELEASE_BLOCK, changed), self.lanes)

    def test_bounded_native_growth_requires_each_guard_and_exact_export_binding(self):
        for command in NATIVE_GROWTH_V2_RELEASE_BLOCK.splitlines(keepends=True):
            for replacement in ['', command * 2, '      # ' + command.lstrip()]:
                with self.subTest(command=command, replacement=replacement), self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(command, replacement), self.lanes)
            moved = self.script.replace(command, '').replace('  protocol-contract)\n',
                '  protocol-contract)\n' + command)
            with self.subTest(command=command, mutation='moved'), self.assertRaises(ValueError):
                check_independent_conformance(moved, self.lanes)
        for before, after in [
            ('TRNM_NATIVE_GROWTH_V2_EXPORT_DIR=', 'WRONG_GROWTH_EXPORT='),
            ('/native-growth-v2"', '/previous-growth-v2"'),
            ('/native-growth-v2-release.log"', '/previous-growth-v2.log"'),
            ('native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen',
             'native_growth_reference_65537_signed_accounts_and_cold_reopen'),
        ]:
            changed = NATIVE_GROWTH_V2_RELEASE_BLOCK.replace(before, after)
            self.assertNotEqual(changed, NATIVE_GROWTH_V2_RELEASE_BLOCK)
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(NATIVE_GROWTH_V2_RELEASE_BLOCK, changed), self.lanes)

    def test_bounded_native_growth_cannot_accept_a_passing_transcript_without_its_export(self):
        # The synthetic producer tests shell/export failure propagation, not Rust.
        with tempfile.TemporaryDirectory(prefix='growth-v2-export-shell-') as temporary:
            root = Path(temporary) / 'receipt with spaces'
            root.mkdir()
            prelude = ('set -euo pipefail\n' + SYNTHETIC_GROWTH_PIPELINE +
                       'cargo() { synthetic_growth_v2_native; rm "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR/native.json"; }\n'
                       'trnm_native_receipt_root="$TRNM_CI_RECEIPT_DIR"\n')
            result = subprocess.run(['bash', '-c', prelude + NATIVE_GROWTH_V2_RELEASE_BLOCK +
                'touch "$TRNM_CI_RECEIPT_DIR/incorrect-success"\n'], cwd=ROOT,
                env={'PATH': '/usr/bin:/bin', 'TRNM_CI_RECEIPT_DIR': str(root)},
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue((root / 'native-growth-v2-release.log').is_file())
            self.assertFalse((root / 'incorrect-success').exists())

    def test_native_growth_libtest_check_must_precede_sqlite_readback(self):
        lines = NATIVE_GROWTH_RELEASE_BLOCK.splitlines(keepends=True)
        for indices in [(4, 5), (5, 8)]:
            changed = lines.copy()
            first, second = indices
            changed[first], changed[second] = changed[second], changed[first]
            with self.subTest(indices=indices), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(NATIVE_GROWTH_RELEASE_BLOCK,
                    ''.join(changed)), self.lanes)
        moved = self.script.replace(NATIVE_GROWTH_RELEASE_BLOCK, '').replace(
            '  protocol-contract)\n', '  protocol-contract)\n' + NATIVE_GROWTH_RELEASE_BLOCK)
        with self.assertRaises(ValueError):
            check_independent_conformance(moved, self.lanes)
        duplicated = self.script.replace('  fuzz-smoke)\n',
            '  fuzz-smoke)\n' + NATIVE_GROWTH_RELEASE_BLOCK)
        with self.assertRaises(ValueError):
            check_independent_conformance(duplicated, self.lanes)

    def test_growth_sqlite_readback_failure_remains_a_shell_failure(self):
        # Synthetic cargo/checker exercise only pipeline plumbing and failure
        # propagation. The actual SQLite oracle has separate native/synthetic CI.
        with tempfile.TemporaryDirectory(prefix='growth-readback-shell-') as temporary:
            root = Path(temporary) / 'receipt with spaces'
            root.mkdir()
            prelude = ('set -euo pipefail\n' + SYNTHETIC_GROWTH_PIPELINE +
                       'cargo() { synthetic_growth_native; }\n'
                       'trnm_native_receipt_root="$TRNM_CI_RECEIPT_DIR"\n')
            result = subprocess.run(['bash', '-c', prelude + NATIVE_GROWTH_RELEASE_BLOCK +
                'touch "$TRNM_CI_RECEIPT_DIR/incorrect-success"\n'], cwd=ROOT,
                env={'PATH': '/usr/bin:/bin', 'TRNM_CI_RECEIPT_DIR': str(root),
                     'TRNM_TEST_READBACK_STATUS': '19'}, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 19, result.stderr)
            self.assertTrue((root / 'native-growth-reference-release.log').is_file())
            self.assertTrue((root / 'native-growth-reference/readback.json').is_file())
            self.assertFalse((root / 'incorrect-success').exists())

    def test_reward_budget_controls_cannot_be_omitted_duplicated_or_moved(self):
        command = '    python3 formal/pon-nakamoto-v1/test_reward_budget_oracle.py\n'
        original = (ROOT / 'scripts/ci/ci_job.sh').read_text()
        for label, changed in [('omitted', original.replace(command, '')),
                               ('duplicated', original.replace(command, command * 2)),
                               ('moved', original.replace(command, '').replace(
                                   '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command))]:
            with self.subTest(change=label), self.assertRaisesRegex(ValueError, 'reward budget'):
                check_independent_conformance(changed, self.lanes)

    def test_demand_upgrade_controls_cannot_be_omitted_duplicated_moved_or_swallowed(self):
        for name in ('test_demand_evidence.py', 'test_upgrade_policy.py'):
            command = '    python3 formal/pon-nakamoto-v1/' + name + ' -v\n'
            original = (ROOT / 'scripts/ci/ci_job.sh').read_text()
            for label, changed in [('omitted', original.replace(command, '')),
                                   ('duplicated', original.replace(command, command * 2)),
                                   ('swallowed', original.replace(command, command.rstrip() + ' || true\n')),
                                   ('moved', original.replace(command, '').replace(
                                       '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command))]:
                with self.subTest(command=name, change=label), self.assertRaisesRegex(ValueError, 'demand evidence'):
                    check_independent_conformance(changed, self.lanes)

    def test_native_lifecycle_cost_controls_cannot_be_omitted_duplicated_moved_or_swallowed(self):
        command = '    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example pon_w1_lifecycle_cost_v4\n'
        self.assertEqual(self.script.count(command), 1)
        for label, changed in [('omitted', self.script.replace(command, '')),
                               ('duplicated', self.script.replace(command, command * 2)),
                               ('swallowed', self.script.replace(command, command.rstrip() + ' || true\n')),
                               ('commented', self.script.replace(command, '    # ' + command.lstrip())),
                               ('moved', self.script.replace(command, '').replace(
                                   '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command))]:
            with self.subTest(change=label), self.assertRaisesRegex(ValueError, 'native lifecycle cost'):
                check_independent_conformance(changed, self.lanes)

    def test_native_demand_controls_cannot_be_omitted_duplicated_moved_or_swallowed(self):
        from check_ci_contract import NATIVE_DEMAND_CONTRACTS
        command = NATIVE_DEMAND_CONTRACTS
        for label, changed in [('omitted', self.script.replace(command, '')),
                               ('duplicated', self.script.replace(command, command * 2)),
                               ('swallowed', self.script.replace(command, command.rstrip() + ' || true\n')),
                               ('moved', self.script.replace(command, '').replace(
                                   '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command))]:
            with self.subTest(change=label), self.assertRaisesRegex(ValueError, 'native demand'):
                check_independent_conformance(changed, self.lanes)

    def test_parent_material_checks_cannot_be_omitted_duplicated_or_moved(self):
        for command in ('    python3 scripts/test_llm_parent_material.py\n',
                        '    python3 scripts/test_llm_runtime_parent_step.py\n'):
            for changed in [self.script.replace(command, ''),
                            self.script.replace(command, '    true # omitted parent preflight\n'),
                            self.script.replace(command, command * 2),
                            self.script.replace(command, '').replace('  fuzz-smoke)\n',
                                '  fuzz-smoke)\n' + command)]:
                with self.subTest(command=command, changed=changed), self.assertRaisesRegex(ValueError, 'parent material'):
                    check_independent_conformance(changed, self.lanes)

    def test_parent_commands_cannot_be_skipped_by_false_shell_branch(self):
        # Only a synthetic failing shell function runs; no model/native command.
        for command in ('    python3 scripts/test_llm_parent_material.py\n',
                        '    python3 scripts/test_llm_runtime_parent_step.py\n'):
            skipped = '    if false; then\n' + command + '    fi\n'
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, 'straight-line command sequence'):
                    check_independent_conformance(self.script.replace(command, skipped), self.lanes)
                prelude = ('set -euo pipefail\n'
                           'python3() { printf "synthetic parent test called\\n"; return 19; }\n')
                normal = subprocess.run(['bash', '-c', prelude + command +
                    'printf "synthetic lane continued\\n"\n'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(normal.returncode, 19, normal.stderr)
                self.assertEqual(normal.stdout, 'synthetic parent test called\n')
                bypass = subprocess.run(['bash', '-c', prelude + skipped +
                    'printf "synthetic lane continued\\n"\n'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(bypass.returncode, 0, bypass.stderr)
                self.assertEqual(bypass.stdout, 'synthetic lane continued\n')

    def test_parent_commands_cannot_have_failures_swallowed_by_shell_condition(self):
        # Bash suppresses errexit in an if condition despite the original set -e.
        for command in ('    python3 scripts/test_llm_parent_material.py\n',
                        '    python3 scripts/test_llm_runtime_parent_step.py\n'):
            conditional = '    if\n' + command + '    then\n      :\n    fi\n'
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, 'straight-line command sequence'):
                    check_independent_conformance(self.script.replace(command, conditional), self.lanes)
                prelude = ('set -euo pipefail\n'
                           'python3() { printf "synthetic parent test called\\n"; return 19; }\n')
                normal = subprocess.run(['bash', '-c', prelude + command +
                    'printf "synthetic lane continued\\n"\n'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(normal.returncode, 19, normal.stderr)
                self.assertEqual(normal.stdout, 'synthetic parent test called\n')
                bypass = subprocess.run(['bash', '-c', prelude + conditional +
                    'printf "synthetic lane continued\\n"\n'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(bypass.returncode, 0, bypass.stderr)
                self.assertEqual(bypass.stdout,
                                 'synthetic parent test called\nsynthetic lane continued\n')

    def test_selected_lane_cannot_be_wrapped_in_an_outer_shell_condition(self):
        start = self.script.index('case "${1:?required job}" in\n')
        prefix, dispatch = self.script[:start], self.script[start:]
        variants = {
            'false outer branch': prefix + 'if false; then\n' + dispatch + 'fi\n',
            'outer condition swallows failure': prefix + 'if\n' + dispatch + 'then :; fi\n',
        }
        for label, changed in variants.items():
            with self.subTest(change=label), self.assertRaisesRegex(ValueError, 'lane dispatch'):
                check_independent_conformance(changed, self.lanes)

    def test_useful_cell_relation_controls_cannot_be_removed_skipped_duplicated_or_moved(self):
        for name in ('test_useful_cell_numeric_v1.py', 'test_useful_cell_relation_v1.py',
                     'test_useful_cell_attempt_journal_v1.py', 'test_grouped_delivery_cost_v1.py',
                     'test_useful_cell_execution_v2.py', 'test_useful_cell_relation_v2.py',
                     'test_useful_cell_relation_v2_adversarial.py', 'test_useful_cell_source_guard_v2.py',
                     'test_useful_cell_multimodal_execution_v3.py',
                     'test_useful_cell_multimodal_relation_v3.py',
                     'test_lifecycle_cost_v1.py', 'test_cell_lottery_cost_audit_v1.py',
                     'test_service_work_settlement_v1.py', 'test_four_propositions_v1.py',
                     'test_four_propositions_w1_v2.py'):
            command = '    python3 formal/pon-nakamoto-v1/' + name + ' -v\n'
            self.assertEqual(self.script.count(command), 1)
            variants = {
                'removed': self.script.replace(command, ''),
                'stubbed': self.script.replace(command, '    true # omitted useful relation\n'),
                'duplicated': self.script.replace(command, command * 2),
                'skipped': self.script.replace(command, '    if false; then\n' + command + '    fi\n'),
                'swallowed': self.script.replace(command, command.rstrip() + ' || true\n'),
                'moved': self.script.replace(command, '').replace('  fuzz-smoke)\n',
                                                                  '  fuzz-smoke)\n' + command),
            }
            for label, script in variants.items():
                with self.subTest(test=name, mutation=label), self.assertRaises(ValueError):
                    check_independent_conformance(script, self.lanes)

    def test_integration_legacy_reorg_reader_retains_its_mandatory_lane(self):
        command = '    python3 scripts/ci/test_run_legacy_reorg_root_abba.py\n'
        self.assertEqual(self.script.count(command), 1)
        check_independent_conformance(self.script, self.lanes)
        variants = {
            'removed': self.script.replace(command, ''),
            'duplicated': self.script.replace(command, command * 2),
            'stubbed': self.script.replace(command, '    true # ' + command.lstrip()),
            'skipped': self.script.replace(command, '    if false; then\n' + command + '    fi\n'),
            'swallowed': self.script.replace(command, command.rstrip() + ' || true\n'),
            'other-lane-duplicate': self.script.replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
            'moved': self.script.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command),
        }
        for label, changed in variants.items():
            with self.subTest(mutation=label), self.assertRaises(ValueError):
                check_independent_conformance(changed, self.lanes)

    def test_native_cell_suite_cannot_disappear_from_mandatory_conformance(self):
        selector = ' --test cell_native_v1'
        self.assertEqual(self.script.count(selector), 1)
        command = next(line for line in self.script.splitlines(keepends=True)
                       if selector in line)
        for replacement in (command.replace(selector, ''),
                            command.replace(selector, selector * 2),
                            '    if false; then\n' + command + '    fi\n',
                            command.rstrip() + ' || true\n'):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(command, replacement), self.lanes)

    def test_original_campaign_reader_keeps_original_pins_and_lane(self):
        for replacement in ['', ORIGINAL_CAMPAIGN_READER * 2,
                            ORIGINAL_CAMPAIGN_READER.replace('python3', 'true # python3'),
                            ORIGINAL_CAMPAIGN_READER.replace('--retained-subset', ''),
                            ORIGINAL_CAMPAIGN_READER.replace('9e705ccf75b7318dcc4bda4815956f58beb10e72', '0' * 40)]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(ORIGINAL_CAMPAIGN_READER, replacement), self.lanes)
        moved = self.script.replace(ORIGINAL_CAMPAIGN_READER, '').replace(
            '  fuzz-smoke)\n', '  fuzz-smoke)\n' + ORIGINAL_CAMPAIGN_READER)
        with self.assertRaises(ValueError):
            check_independent_conformance(moved, self.lanes)

    def test_new_evolution_and_cost_checks_cannot_be_removed_skipped_duplicated_or_moved(self):
        for block in [MODEL_EVOLUTION_ORACLES, COST_BOUNDARY_READERS]:
            for command in block.splitlines(keepends=True):
                for replacement in ['', command * 2, command.replace('python3', 'true # python3')]:
                    with self.subTest(command=command, replacement=replacement):
                        with self.assertRaises(ValueError):
                            check_independent_conformance(self.script.replace(command, replacement), self.lanes)
                moved = self.script.replace(command, '').replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
                with self.assertRaises(ValueError):
                    check_independent_conformance(moved, self.lanes)

    def test_branch_schedule_export_and_full_reader_cannot_be_omitted_or_forged(self):
        commands = [line + '\n' for line in self.script.splitlines()
                    if 'TRNM_WORK_SCHEDULE_RESEARCH_DIR' in line
                    or 'trnm_schedule_' in line]
        self.assertGreaterEqual(len(commands), 9)
        for command in commands:
            for replacement in ('', command * 2, '      true # suppressed schedule evidence\n'):
                with self.subTest(command=command, replacement=replacement):
                    with self.assertRaises(ValueError):
                        check_independent_conformance(self.script.replace(command, replacement), self.lanes)
        for old, new in [
            ('in pnh1-authenticated pgh2-growth; do', 'in pnh1-authenticated; do'),
            ('sha256sum "$trnm_schedule_dir/report.json"', 'printf stale-prior-report'),
            ('--report-sha256 "$trnm_schedule_digest"', '--skip-full-work'),
        ]:
            with self.subTest(old=old):
                with self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(old, new), self.lanes)

    def test_native_daa_reader_requires_fresh_full_work_export_and_actual_digest(self):
        lines = [line + '\n' for line in self.script.splitlines()
                 if 'TRNM_DAA_EVIDENCE_DIR' in line]
        self.assertEqual(len(lines), 6)
        for command in lines:
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(command, ''), self.lanes)
        changed = self.script.replace('sha256sum "$TRNM_DAA_EVIDENCE_DIR/daa-bounds.json"',
                                      'printf stale-prior-report')
        with self.assertRaises(ValueError):
            check_independent_conformance(changed, self.lanes)

    def test_joint_consensus_arithmetic_controls_cannot_be_removed_skipped_or_swallowed(self):
        command = '    python3 formal/pon-nakamoto-v1/test_joint_consensus_boundaries.py -v\n'
        self.assertEqual(self.script.count(command), 1)
        replacements = ('', command * 2, '    true # omitted joint consensus controls\n',
                        '    if false; then\n' + command + '    fi\n',
                        command.rstrip() + ' || true\n',
                        '    if\n' + command + '    then :; fi\n')
        for replacement in replacements:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                check_independent_conformance(self.script.replace(command, replacement), self.lanes)
        moved = self.script.replace(command, '').replace(
            '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
        with self.assertRaises(ValueError):
            check_independent_conformance(moved, self.lanes)

    def _assert_native_daa_requires_both_fresh_profiles_and_current_report_digests(
            self, selector, report_filename):
        lines = [line + '\n' for line in self.script.splitlines()
                 if selector in line]
        self.assertEqual(len(lines), 8)
        for command in lines:
            for replacement in ('', command * 2):
                with self.subTest(command=command, replacement=replacement), self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(command, replacement), self.lanes)
            moved = self.script.replace(command, '').replace(
                '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
            with self.subTest(command=command, moved=True), self.assertRaises(ValueError):
                check_independent_conformance(moved, self.lanes)
        for leaked in ('    export ' + selector + '=/tmp/stale-other-run\n',
                       '    unset ' + selector + '\n'):
            changed = self.script.replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + leaked)
            with self.subTest(leaked=leaked), self.assertRaises(ValueError):
                check_independent_conformance(changed, self.lanes)
        for profile, other in [('pnh1-authenticated', 'pgh2-growth'),
                               ('pgh2-growth', 'pnh1-authenticated')]:
            raw_argument = '--raw-dir "$' + selector + '/' + profile + '"'
            commands = [line for line in lines if 'python3 ' in line and raw_argument in line]
            self.assertEqual(len(commands), 2)
            for command in commands:
                replacements = (
                    command.replace('python3 ', 'true # python3 '),
                    '      if false; then\n' + command + '      fi\n',
                    command.rstrip() + ' || true\n',
                    command.replace(raw_argument, '--raw-dir "/tmp/stale-other-run"'),
                    command.replace(raw_argument, '--raw-dir "$' + selector + '"'),
                    command.replace(raw_argument, raw_argument.replace(profile, other)),
                )
                for replacement in replacements:
                    with self.subTest(profile=profile, replacement=replacement), self.assertRaises(ValueError):
                        check_independent_conformance(self.script.replace(command, replacement), self.lanes)
            reader = next(command for command in commands if '--expected-report-sha256' in command)
            digest = ('$(sha256sum "$' + selector + '/' + profile
                      + '/' + report_filename + '" | cut -d \' \' -f 1)')
            self.assertIn(digest, reader)
            replacements = [reader.replace(digest, value)
                            for value in ('0' * 64, '$(printf stale-prior-report)',
                                          digest.replace(profile, other))]
            replacements.append(reader.replace('--expected-report-sha256 "' + digest + '" ', ''))
            for replacement in replacements:
                with self.subTest(profile=profile, replacement=replacement), self.assertRaises(ValueError):
                    check_independent_conformance(self.script.replace(reader, replacement), self.lanes)

    def test_native_joint_daa_requires_both_fresh_profiles_and_current_report_digests(self):
        self._assert_native_daa_requires_both_fresh_profiles_and_current_report_digests(
            'TRNM_JOINT_DAA_EVIDENCE_DIR', 'joint-daa.json')

    def test_native_monotone_daa_requires_both_fresh_profiles_and_current_report_digests(self):
        self._assert_native_daa_requires_both_fresh_profiles_and_current_report_digests(
            'TRNM_MONOTONE_DAA_EVIDENCE_DIR', 'monotone-daa.json')

    def test_cost_counterexamples_require_their_real_input_arguments(self):
        for command in [COST_BOUNDARY_READERS.splitlines(keepends=True)[0],
                        '      python3 scripts/ci/test_pon_daa_schedule_reader.py --raw-dir "$TRNM_DAA_EVIDENCE_DIR"\n']:
            for replacement in [command.split(' --raw-dir')[0] + '\n',
                                command.split(' --raw-dir')[0] + ' --raw-dir /tmp/stale-other-run\n']:
                with self.subTest(command=command, replacement=replacement):
                    with self.assertRaises(ValueError):
                        check_independent_conformance(self.script.replace(command, replacement), self.lanes)

    def test_quorum_checks_cannot_be_removed_duplicated_skipped_or_rewrite_vectors(self):
        for command in EVALUATION_QUORUM_ORACLE.splitlines(keepends=True):
            for replacement in ['', '    true # omitted quorum reference\n', command * 2,
                                command.replace('python3', 'true # python3'),
                                command.rstrip('\n') + ' --write\n']:
                with self.subTest(command=command, replacement=replacement):
                    with self.assertRaisesRegex(ValueError, 'evaluation quorum oracle'):
                        check_independent_conformance(self.script.replace(command, replacement), self.lanes)

    def test_quorum_checks_cannot_move_to_another_lane_or_reverse_verification(self):
        commands = EVALUATION_QUORUM_ORACLE.splitlines(keepends=True)
        changed = [self.script.replace(EVALUATION_QUORUM_ORACLE, ''.join(reversed(commands)))]
        for command in [*commands, EVALUATION_QUORUM_ORACLE]:
            changed.append(self.script.replace(command, '').replace(
                '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command))
        for script in changed:
            with self.subTest(script=script):
                with self.assertRaisesRegex(ValueError, 'evaluation quorum oracle'):
                    check_independent_conformance(script, self.lanes)


class W1ReuseV3LaneTests(unittest.TestCase):
    """Small real source-owner controls; no native work/cost observation."""

    def test_v3_lane_is_additive_and_keeps_all_four_exact_source_cells(self):
        report = validate(ROOT)
        self.assertEqual(report['native_cost_architectures'], 2)
        self.assertEqual(report['w1_actual_reuse_v3_cells'], 4)
        text = (ROOT / '.github/workflows/trnm-required-baseline.yml').read_text()
        self.assertEqual(text.count('  cross-arch-w1-reuse-v3:\n'), 1)
        self.assertEqual(text.count('run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_w1_reused_cost_v3.py'), 1)

    def test_v3_cannot_skip_rename_rebudget_or_substitute_local_observation(self):
        from check_ci_contract import W1_REUSE_V3_JOB, check_w1_reuse_v3
        for old, new in (
            ('arch: [x64, arm64]', 'arch: [x64]'),
            ('source: [head, prospective-merge]', 'source: [head]'),
            ('      fail-fast: false', '      fail-fast: true'),
            ('    timeout-minutes: 155', '    timeout-minutes: 180'),
            ("    if: github.event_name == 'pull_request'", '    if: false'),
            ('--expected-base "$TRNM_EXPECTED_BASE_SHA" ', ''),
            ('--expected-merge "$TRNM_EXPECTED_SOURCE_SHA"', '--expected-merge "$TRNM_EXPECTED_CANDIDATE_SHA"'),
            ('--output "$RUNNER_TEMP/ci-observations/source-after.json"', '--output /tmp/old-source.json'),
            ('run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_w1_reused_cost_v3.py', 'run: true # python3 scripts/ci/run_w1_reused_cost_v3.py'),
            ('env -u CARGO_INCREMENTAL python3', 'python3'),
            ('env -u CARGO_INCREMENTAL python3', 'env -u CARGO_INCREMENTAL -u RUSTFLAGS python3'),
            ('run_w1_reused_cost_v3.py --arch', 'run_w1_reused_cost_v3.py --local --arch'),
            ('run: bash scripts/project-preflight.sh --audit', 'run: true # bash scripts/project-preflight.sh --audit'),
            ('      - name: Check original repository boundary before native V3 build\n        run: bash scripts/project-preflight.sh --audit\n', ''),
            ('rustup toolchain install 1.95.0', 'rustup toolchain install stable'),
            ('        if: always()\n', ''),
            ('name: w1-reuse-v3-${{ matrix.source }}-', 'name: cost-'),
            ('          if-no-files-found: error', '          if-no-files-found: ignore'),
        ):
            with self.subTest(old=old, new=new):
                self.assertIn(old, W1_REUSE_V3_JOB)
                with self.assertRaisesRegex(ValueError, 'four exact W1 V3'):
                    check_w1_reuse_v3(W1_REUSE_V3_JOB.replace(old, new, 1).split('\n', 1)[1])
        for changed in ('', W1_REUSE_V3_JOB * 2):
            with self.assertRaises(ValueError):
                check_w1_reuse_v3(changed)

    def test_actual_v3_source_shell_binds_head_ordered_merge_and_unchanged_bytes(self):
        import json
        import os
        import re
        import textwrap

        workflow = (ROOT / '.github/workflows/trnm-required-baseline.yml').read_text()
        block = workflow.split('  cross-arch-w1-reuse-v3:\n', 1)[1].split('\n  cross-arch-cost-consistency:', 1)[0]
        commands = re.findall(r'        run: \|\n(.*?)(?=      - name:)', block, re.S)
        before, after = [textwrap.dedent(value) for value in commands if 'verify_ci_source.py' in value]
        with tempfile.TemporaryDirectory(prefix='w1-v3-source-shell-') as temporary:
            directory = Path(temporary)
            checkout, output = directory / 'repo', directory / 'receipts'
            (checkout / 'scripts/ci').mkdir(parents=True)
            output.mkdir()
            shutil.copyfile(ROOT / 'scripts/ci/verify_ci_source.py', checkout / 'scripts/ci/verify_ci_source.py')

            def git(*args):
                return subprocess.check_output(['git', *args], cwd=checkout, text=True, stderr=subprocess.DEVNULL).strip()

            git('init', '-q', '-b', 'base')
            git('config', 'user.name', 'W1 V3 source test')
            git('config', 'user.email', 'source-test@example.invalid')
            (checkout / 'actual').write_text('base\n')
            git('add', '.')
            git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            git('checkout', '-qb', 'candidate')
            (checkout / 'actual').write_text('candidate\n')
            git('commit', '-am', 'candidate', '-q')
            head = git('rev-parse', 'HEAD')
            env = dict(os.environ, RUNNER_TEMP=str(output), PYTHONDONTWRITEBYTECODE='1',
                       TRNM_COST_SOURCE_KIND='head', TRNM_EXPECTED_CANDIDATE_SHA=head,
                       TRNM_EXPECTED_BASE_SHA=base, TRNM_EXPECTED_SOURCE_SHA=head)

            def run(command):
                return subprocess.run(['bash', '-euo', 'pipefail', '-c', command], cwd=checkout,
                                      env=env, text=True, capture_output=True)

            self.assertEqual(run(before).returncode, 0)
            initial = json.loads((output / 'ci-observations/source-before.json').read_text())
            self.assertEqual(initial['tested_commit'], head)
            self.assertTrue(initial['tracked_worktree_verified'])
            (checkout / 'actual').write_text('tampered\n')
            self.assertNotEqual(run(after).returncode, 0)
            git('checkout', '--', 'actual')
            self.assertEqual(run(after).returncode, 0)
            git('checkout', '-q', 'base')
            git('merge', '--no-ff', '-qm', 'actual ordered merge', 'candidate')
            merge = git('rev-parse', 'HEAD')
            env.update(TRNM_COST_SOURCE_KIND='prospective-merge', TRNM_EXPECTED_SOURCE_SHA=merge)
            self.assertEqual(run(before).returncode, 0)
            merged = json.loads((output / 'ci-observations/source-before.json').read_text())
            self.assertEqual(merged['tested_commit'], merge)
            self.assertEqual(merged['candidate'], head)
            self.assertEqual(merged['base'], base)
            env['TRNM_EXPECTED_BASE_SHA'] = head
            self.assertNotEqual(run(after).returncode, 0)
            env['TRNM_EXPECTED_BASE_SHA'] = base
            self.assertEqual(run(after).returncode, 0)


class PqReleaseAuthorityCiTests(unittest.TestCase):
    """Exercise the real workflow readers/loop with explicit synthetic logs.

    The loop tests substitute only recorded Cargo execution. They keep the real
    exact-test reader and never claim that synthetic libtest output is native work.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-pq-authority-ci-')
        self.root = Path(self.temporary.name)
        for relative in (PQ_RELEASE_WORKFLOW, PQ_RELEASE_MANIFEST,
                         'config/pon/pq-initial-root-material-required-tests-v1.json', *PQ_ROOT_HARNESS_FILES,
                         'scripts/ci/check_required_native_test.py'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.manifest = json.loads((self.root / PQ_RELEASE_MANIFEST).read_text())

    def tearDown(self):
        self.temporary.cleanup()

    def step(self, name):
        text = (self.root / PQ_RELEASE_WORKFLOW).read_text()
        marker = '      - name: ' + name + '\n'
        self.assertEqual(text.count(marker), 1)
        return marker + text.split(marker, 1)[1].split('\n      - ', 1)[0] + '\n'

    def release_step(self):
        return self.step('Require all release authority and CCH1 controls from the complete Unix registry')

    def harness_step(self):
        return self.step('Run root-quorum codec and policy test doubles without native crypto claims')

    @staticmethod
    def inline_python(step):
        return textwrap.dedent(step.split("<<'PY'\n", 1)[1].split('\n          PY', 1)[0]) + '\n'

    def rejected_source(self, relative, before, after):
        path = self.root / relative
        original = path.read_text()
        self.assertIn(before, original)
        try:
            path.write_text(original.replace(before, after, 1))
            with self.assertRaises(ValueError):
                check_pq_release_authority_controls(self.root)
        finally:
            path.write_text(original)

    def rejected_manifest(self, mutate):
        path = self.root / PQ_RELEASE_MANIFEST
        original = path.read_text()
        altered = json.loads(original)
        mutate(altered)
        try:
            path.write_text(json.dumps(altered))
            with self.assertRaises(ValueError):
                check_pq_release_authority_controls(self.root)
        finally:
            path.write_text(original)

    def registry_log(self, names=None, count=55):
        if names is None:
            names = self.manifest['complete_release_tests']
        return ''.join(name + ': test\n' for name in names) + f'\n{count} tests, 0 benchmarks\n'

    def read_registry(self, text, output):
        output.mkdir(exist_ok=True)
        (output / 'initial-root-release-registry.log').write_text(text)
        return subprocess.run(
            [sys.executable, '-B', '-c', self.inline_python(self.release_step()),
             str(self.root / PQ_RELEASE_MANIFEST), str(output)],
            cwd=self.root, capture_output=True, text=True,
        )

    def read_harness(self, text, output):
        output.mkdir(exist_ok=True)
        log = output / 'root-quorum-harness.log'
        log.write_text(text)
        return subprocess.run(
            [sys.executable, '-B', '-c', self.inline_python(self.harness_step()), str(log)],
            cwd=self.root, capture_output=True, text=True,
        )

    def test_reviewed_groups_complete_registry_and_hosted_execution_are_required(self):
        result = check_pq_release_authority_controls(self.root)
        self.assertEqual(result['groups'], {'original_release': 37, 'initial_root_material': 6,
                                           'quorum_preflight': 9, 'cch1_content_binding': 3})
        self.assertEqual(result['complete_release'], 55)
        self.assertEqual(result['platform_scope'], 'unix')
        self.assertEqual(result['python_test_doubles'], 18)
        self.assertFalse(result['tests_executed'])

    def test_original_initial_root_and_quorum_names_cannot_be_relabelled_together(self):
        for group in PQ_RELEASE_GROUPS:
            with self.subTest(group=group):
                def rename(value):
                    name = value[group + '_tests'][0]
                    value[group + '_tests'][0] = name + '_renamed'
                    index = value['complete_release_tests'].index(name)
                    value['complete_release_tests'][index] = name + '_renamed'
                    value['complete_release_tests'].sort()
                self.rejected_manifest(rename)

    def test_v2_preserves_the_complete_legacy_manifest_and_ordered_groups(self):
        raw = (self.root / 'config/pon/pq-initial-root-material-required-tests-v1.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'a359086820e876a3806acdd1225689ff072ebfe10d455ac3a96d8d7060680693')
        legacy = json.loads(raw)
        for group in ('original_release', 'initial_root_material', 'quorum_preflight'):
            self.assertEqual(self.manifest[group + '_tests'], legacy[group + '_tests'])
        added = self.manifest['cch1_content_binding_tests']
        self.assertEqual(added, [
            'content_v1::tests::complete_artifact_and_all_metadata_enter_the_strong_commitment',
            'content_v1::tests::retained_file_reads_exact_bytes_and_refuses_partial_offset',
            'content_v1::tests::short_long_wrong_locator_and_old_digest_wrapper_are_refused',
        ])
        self.assertEqual(self.manifest['complete_release_tests'],
                         sorted(legacy['complete_release_tests'] + added))

    def test_manifest_and_actual_reader_reject_wrong_unix_scope_or_missing_cch1(self):
        mutations = (
            lambda v: v.__setitem__('schema', 'trnm-pq-initial-root-material-required-tests-v1'),
            lambda v: v.pop('platform_scope'),
            lambda v: v.__setitem__('platform_scope', 'all-platforms'),
            lambda v: v.__setitem__('platform_scope', 'windows'),
            lambda v: v['expected_controls'].pop('cch1_content_binding'),
            lambda v: v['expected_controls'].__setitem__('cch1_content_binding', 3.0),
            lambda v: v.pop('cch1_content_binding_tests'),
            lambda v: v['cch1_content_binding_tests'].pop(),
            lambda v: v['cch1_content_binding_tests'].__setitem__(0, v['original_release_tests'][0]),
            lambda v: v['cch1_content_binding_tests'].__setitem__(0, v['cch1_content_binding_tests'][1]),
        )
        path = self.root / PQ_RELEASE_MANIFEST
        original = path.read_text()
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.rejected_manifest(mutate)
                altered = json.loads(original)
                mutate(altered)
                try:
                    path.write_text(json.dumps(altered))
                    result = self.read_registry(self.registry_log(), self.root / f'v2-negative-{index}')
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    path.write_text(original)

    def test_actual_registry_cannot_substitute_legacy_52_or_non_unix_54(self):
        legacy = json.loads((self.root / 'config/pon/pq-initial-root-material-required-tests-v1.json').read_text())
        legacy_names = legacy['complete_release_tests']
        unix_only = 'content_v1::tests::retained_file_reads_exact_bytes_and_refuses_partial_offset'
        non_unix = [name for name in self.manifest['complete_release_tests'] if name != unix_only]
        self.assertEqual(len(legacy_names), 52)
        self.assertEqual(len(non_unix), 54)
        for index, log in enumerate((self.registry_log(legacy_names, 52),
                                     self.registry_log(legacy_names, 55),
                                     self.registry_log(non_unix, 54),
                                     self.registry_log(non_unix, 55))):
            with self.subTest(registry=index):
                result = self.read_registry(log, self.root / f'legacy-registry-negative-{index}')
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_manifest_rejects_wrong_counts_duplicates_partitions_and_scope_claims(self):
        mutations = [
            lambda v: v['expected_controls'].__setitem__('complete_release', 43),
            lambda v: v['expected_controls'].__setitem__('complete_release', 55.0),
            lambda v: v['expected_controls'].pop('quorum_preflight'),
            lambda v: v.__setitem__('scope', 'immutable-initial-root-public-key-material-only'),
            lambda v: v['complete_release_tests'].pop(),
            lambda v: v['complete_release_tests'].__setitem__(0, v['complete_release_tests'][1]),
            lambda v: v['complete_release_tests'].__setitem__(0, 'unreviewed::test'),
            lambda v: v['quorum_preflight_tests'].__setitem__(0, v['original_release_tests'][0]),
            lambda v: v['quorum_preflight_tests'].__setitem__(0, v['quorum_preflight_tests'][1]),
            lambda v: v.pop('quorum_preflight_tests'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.rejected_manifest(mutate)
        for flag in ('authorization_results_cached', 'signature_results_cached', 'performance_qualified',
                     'production_activation', 'consensus_authority', 'whole_chain_quantum_security_qualified'):
            for value in (True, 0):
                with self.subTest(flag=flag, value=value):
                    self.rejected_manifest(lambda v, flag=flag, value=value: v.__setitem__(flag, value))

    def test_workflow_cannot_reduce_registry_queue_exact_execution_or_readback(self):
        step = self.release_step()
        reader = ('            elif ! python3 scripts/ci/check_required_native_test.py '
                  '"$out/$label.log" --test "$selector" > "$out/$label-execution.json"; then\n')
        changes = [
            ('len(names) != 55', 'len(names) < 55'),
            ('set(names) != sets["complete_release"]', 'not sets["complete_release"].issubset(set(names))'),
            ('for group in groups for index, name', 'for group in groups[:2] for index, name'),
            ('"$selector" -- --exact --show-output', '"$selector" -- --show-output'),
            (reader, '            elif ! true; then\n'),
            ('          test "$failed" = 0\n', '          true\n'),
        ]
        for before, after in changes:
            with self.subTest(before=before):
                self.assertIn(before, step)
                self.rejected_source(PQ_RELEASE_WORKFLOW, step, step.replace(before, after, 1))

    def test_workflow_cannot_skip_or_untrigger_authority_and_harness_controls(self):
        for step in (self.release_step(), self.harness_step()):
            for replacement in ('', step.replace('        shell: bash\n', '        if: false\n        shell: bash\n', 1),
                                step.replace('        shell: bash\n', '        continue-on-error: true\n        shell: bash\n', 1)):
                with self.subTest(step=step.splitlines()[0], replacement=replacement[:80]):
                    self.rejected_source(PQ_RELEASE_WORKFLOW, step, replacement)
        self.rejected_source(PQ_RELEASE_WORKFLOW, '  primitive-interoperability:\n',
                             '  primitive-interoperability:\n    if: false\n')
        for relative in (*PQ_ROOT_HARNESS_FILES, 'scripts/ci/check_ci_contract.py', 'scripts/ci/test_ci_contract.py'):
            self.rejected_source(PQ_RELEASE_WORKFLOW, '      - ' + relative + '\n', '')
        self.rejected_source(PQ_RELEASE_WORKFLOW, 'python3 -B formal/pon-nakamoto-v1/test_pq_root_quorum_research.py -v',
                             'true # python3 -B formal/pon-nakamoto-v1/test_pq_root_quorum_research.py -v')

    def test_harness_source_keeps_all_eighteen_reviewed_test_double_names(self):
        path = self.root / PQ_ROOT_HARNESS_FILES[1]
        module = ast.parse(path.read_text())
        test_class = next(node for node in module.body
                          if isinstance(node, ast.ClassDef) and node.name == 'RootQuorumResearchTests')
        name = next(node.name for node in test_class.body
                    if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        self.rejected_source(PQ_ROOT_HARNESS_FILES[1], 'def ' + name + '(', 'def test_unreviewed(')
        self.rejected_source(PQ_ROOT_HARNESS_FILES[1], 'class RootQuorumResearchTests(', 'class UnreviewedTests(')

    def test_actual_registry_reader_requires_exact_complete_55_and_four_groups(self):
        output = self.root / 'registry-positive'
        result = self.read_registry(self.registry_log(), output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['scope'], 'registry-presence-only')
        rows = [line.split('\t') for line in (output / 'release-authority-required.tsv').read_text().splitlines()]
        self.assertEqual(len(rows), 55)
        self.assertEqual(len({name for _, name in rows}), 55)
        self.assertEqual({name for _, name in rows}, set(self.manifest['complete_release_tests']))
        for prefix, count in (('original-release-', 37), ('initial-root-', 6),
                              ('quorum-preflight-', 9), ('cch1-content-binding-', 3)):
            self.assertEqual(sum(label.startswith(prefix) for label, _ in rows), count)
        names = self.manifest['complete_release_tests']
        invalid = [
            self.registry_log(names[:-1], 54),
            self.registry_log(names + ['unreviewed::test'], 56),
            self.registry_log(names[:-1] + [names[0]], 55),
            self.registry_log(names[:-1] + ['unreviewed::test'], 55),
            self.registry_log(count=43),
            self.registry_log() + '55 tests, 0 benchmarks\n',
            ''.join(name + ': test\n' for name in names),
        ]
        for index, log in enumerate(invalid):
            with self.subTest(index=index):
                result = self.read_registry(log, self.root / f'registry-negative-{index}')
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_actual_exact_loop_checks_every_result_and_preserves_failure_status(self):
        # Only the recorder/Cargo call is synthetic; the workflow loop and its
        # check_required_native_test.py invocation below are the original bytes.
        prefix = r'''set -euo pipefail
source_args=()
out="$TRNM_SYNTHETIC_OUTPUT"
python3() {
  if test "${1:-}" != scripts/ci/record_pq_native_command.py; then
    command python3 "$@"
    return
  fi
  shift
  test "${1:-}" = --label || return 99
  local label="$2"
  shift 2
  test "${1:-}" = --output || return 99
  local directory="$2"
  shift 2
  test "${1:-}" = -- || return 99
  shift
  local part
  for part in cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-release-bundle --lib; do
    test "${1:-}" = "$part" || return 99
    shift
  done
  local selector="$1"
  shift
  test "$*" = '-- --exact --show-output --test-threads=1' || return 99
  printf '%s\t%s\n' "$label" "$selector" >> "$directory/calls.tsv"
  local mode=pass
  if test "$selector" = "$TRNM_SYNTHETIC_TARGET"; then
    mode="$TRNM_SYNTHETIC_MODE"
  fi
  case "$mode" in
    zero)
      printf '%s\n' 'running 0 tests' 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 55 filtered out; finished in 0.00s' > "$directory/$label.log"
      ;;
    ignored)
      printf 'running 1 test\ntest %s ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 54 filtered out; finished in 0.00s\n' "$selector" > "$directory/$label.log"
      ;;
    *)
      local actual="$selector"
      if test "$mode" = wrong; then actual="${selector}::wrong"; fi
      printf 'running 1 test\ntest %s ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 54 filtered out; finished in 0.00s\n' "$actual" > "$directory/$label.log"
      if test "$mode" = duplicate; then
        printf 'test %s ... ok\n' "$selector" >> "$directory/$label.log"
      fi
      ;;
  esac
  if test "$mode" = process; then return 7; fi
  return 0
}
'''
        loop = textwrap.dedent(self.release_step().split('          PY\n', 1)[1])
        target = self.manifest['quorum_preflight_tests'][-1]
        for mode in ('pass', 'zero', 'ignored', 'wrong', 'duplicate', 'process'):
            with self.subTest(mode=mode):
                output = self.root / ('loop-' + mode)
                registry = self.read_registry(self.registry_log(), output)
                self.assertEqual(registry.returncode, 0, registry.stderr)
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TRNM_SYNTHETIC_OUTPUT=str(output),
                           TRNM_SYNTHETIC_MODE=mode, TRNM_SYNTHETIC_TARGET=target)
                result = subprocess.run(['bash', '-c', prefix + loop], cwd=self.root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mode == 'pass', result.stderr)
                calls = [line.split('\t') for line in (output / 'calls.tsv').read_text().splitlines()]
                self.assertEqual(len(calls), 55)
                self.assertEqual({name for _, name in calls}, set(self.manifest['complete_release_tests']))
                for label, name in calls:
                    if mode != 'pass' and name == target:
                        continue
                    execution = json.loads((output / (label + '-execution.json')).read_text())
                    self.assertEqual(execution['test'], name)
                    self.assertEqual(execution['executed_tests'], 1)

    def test_actual_python_harness_runs_all_eighteen_and_readback_has_no_native_claim(self):
        run = subprocess.run([sys.executable, '-B', str(self.root / PQ_ROOT_HARNESS_FILES[1]), '-v'],
                             cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(run.returncode, 0, run.stdout)
        result = self.read_harness(run.stdout, self.root / 'harness-positive')
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed['executed_tests'], 18)
        self.assertEqual(observed['scope'], 'python-codec-policy-test-doubles-only')
        self.assertIs(observed['native_crypto_observed'], False)
        self.assertIs(observed['production_activation'], False)
        rows = run.stdout.splitlines()
        first = next(line for line in rows if line.startswith('test_'))
        invalid = [
            'Ran 0 tests in 0.00s\n\nOK\n',
            run.stdout.replace(first + '\n', '', 1),
            run.stdout + first + '\n',
            run.stdout.replace(first, first.replace(' ... ok', ' ... skipped'), 1),
            run.stdout.replace(first, first.replace('RootQuorumResearchTests', 'UnreviewedTests'), 1),
            run.stdout.replace('Ran 18 tests', 'Ran 17 tests'),
            run.stdout.replace('\nOK\n', '\nOK (skipped=1)\n'),
            run.stdout.replace('\nOK\n', '\nFAILED (failures=1)\n'),
        ]
        first_name = first.split(' ', 1)[0]
        invalid.append(run.stdout.replace(first_name, 'test_unreviewed'))
        for index, log in enumerate(invalid):
            with self.subTest(index=index):
                result = self.read_harness(log, self.root / f'harness-negative-{index}')
                self.assertNotEqual(result.returncode, 0, result.stdout)


class CiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-ci-contract-')
        cls.root = Path(cls.temporary.name) / 'source'
        ignored = shutil.ignore_patterns('.git', 'target', '__pycache__', 'artifacts')

        def ignore(directory, names):
            excluded = ignored(directory, names)
            if Path(directory) == ROOT:
                # These validators consume source and literal workflow pins,
                # not retained execution archives. Positive fixture validation
                # still rejects any future pin whose input is missing.
                excluded.add('evidence')
            return excluded

        shutil.copytree(ROOT, cls.root, ignore=ignore)

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

    def test_missing_useful_cell_sources_fail_contract_and_actual_ci_command(self):
        script = (self.root / 'scripts/ci/ci_job.sh').read_text()
        for name in ('test_useful_cell_numeric_v1.py', 'test_useful_cell_relation_v1.py',
                     'test_useful_cell_attempt_journal_v1.py', 'test_grouped_delivery_cost_v1.py',
                     'test_useful_cell_execution_v2.py', 'test_useful_cell_relation_v2.py',
                     'test_useful_cell_relation_v2_adversarial.py', 'test_useful_cell_source_guard_v2.py',
                     'test_useful_cell_multimodal_execution_v3.py',
                     'test_useful_cell_multimodal_relation_v3.py',
                     'test_lifecycle_cost_v1.py', 'test_cell_lottery_cost_audit_v1.py',
                     'test_service_work_settlement_v1.py', 'test_four_propositions_v1.py',
                     'test_four_propositions_w1_v2.py'):
            path = self.root / 'formal/pon-nakamoto-v1' / name
            command = next(line.strip() for line in script.splitlines()
                           if line.strip() == 'python3 formal/pon-nakamoto-v1/' + name + ' -v')
            raw = path.read_bytes()
            try:
                path.unlink()
                with self.subTest(test=name), self.assertRaisesRegex(
                        ValueError, 'required useful Cell test source is missing'):
                    validate(self.root)
                result = subprocess.run(['bash', '-euo', 'pipefail', '-c', command],
                                        cwd=self.root, text=True, capture_output=True)
                with self.subTest(test=name, actual_command=command):
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(name, result.stderr)
                    self.assertNotIn('Ran 0 tests', result.stderr)
            finally:
                path.write_bytes(raw)

    def test_zero_native_execution_cannot_be_removed_skipped_or_replaced(self):
        for replacement in ['', ZERO_RUN_STEP.replace('        if: always()\n', ''),
                            ZERO_RUN_STEP.replace('run: env -u CARGO_INCREMENTAL python3', 'run: true # python3'),
                            ZERO_RUN_STEP.replace('env -u CARGO_INCREMENTAL python3', 'python3'),
                            ZERO_RUN_STEP.replace('env -u CARGO_INCREMENTAL python3',
                                                  'env -u CARGO_INCREMENTAL -u RUSTFLAGS python3')]:
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
        original = '    timeout-minutes: 180\n'
        for replacement in ['', '    timeout-minutes: 45\n', '    timeout-minutes: 90\n',
                            original + original]:
            with self.subTest(replacement=replacement):
                self.rejected(path, original, replacement)

    def test_merge_rust_budget_must_match_head_without_expanding_other_lanes(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        original = "    timeout-minutes: ${{ matrix.lane == 'rust-baseline' && 180 || 45 }}\n"
        for replacement in ['', '    timeout-minutes: 45\n', '    timeout-minutes: 180\n',
                            original.replace('180 || 45', '90 || 45'),
                            original.replace('==', '!='), original.replace('180 || 45', '45 || 180'),
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

    def test_six_workpackage_readers_execute_once_in_repository_truth(self):
        path = 'scripts/ci/ci_job.sh'
        for name in ('test_six_workpackage_native_rosters.py',
                     'test_w1_full_v2_disposition.py',
                     'test_pon_w1_preparation_strategy_reader_v4.py'):
            command = '    python3 scripts/ci/' + name + '\n'
            for replacement in ('', command * 2, '    true # skipped six-workpackage reader\n'):
                with self.subTest(name=name, replacement=replacement):
                    self.rejected(path, command, replacement)
            original = (self.root / path).read_text()
            changed = original.replace(command, '').replace('  protocol-contract)\n',
                                                            '  protocol-contract)\n' + command)
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
                            MAINTENANCE_RUN_STEP.replace('run: env -u CARGO_INCREMENTAL python3', 'run: true # python3'),
                            MAINTENANCE_RUN_STEP.replace('env -u CARGO_INCREMENTAL python3', 'python3'),
                            MAINTENANCE_RUN_STEP.replace('env -u CARGO_INCREMENTAL python3',
                                                         'env -u CARGO_INCREMENTAL -u RUSTFLAGS python3'),
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

    def test_root_recovery_suite_files_cannot_be_deleted_or_replaced_by_symlinks(self):
        paths = (
            'formal/pon-nakamoto-v1/test_pq_root_recovery_signatures_v2.py',
            'formal/pon-nakamoto-v1/test_pq_root_effect_readback_v2.py',
            'formal/pon-nakamoto-v1/test_pq_root_recovery_signatures_native_v2.py',
            'formal/pon-nakamoto-v1/test_pq_root_effect_readback_native_v2.py',
            'formal/pon-nakamoto-v1/test_pq_root_recovery_journal_native_v2.py',
        )
        for relative in paths:
            path = self.root / relative
            original = path.read_bytes()
            try:
                path.unlink()
                with self.subTest(path=relative, change='deleted'), self.assertRaisesRegex(
                        ValueError, 'root recovery CI suite must remain a regular source file'):
                    validate(self.root)
                path.symlink_to('test_pq_root_recovery_policy_v1.py')
                with self.subTest(path=relative, change='symlink'), self.assertRaisesRegex(
                        ValueError, 'root recovery CI suite must remain a regular source file'):
                    validate(self.root)
            finally:
                if path.is_symlink():
                    path.unlink()
                path.write_bytes(original)

    def test_pq_lifetime_budget_commands_cannot_disappear_or_move(self):
        path = 'scripts/ci/ci_job.sh'
        for command in ('    python3 scripts/ci/test_pq_lifetime_budget.py\n',
                        '    python3 scripts/ci/pq_lifetime_budget.py\n',
                        '    python3 scripts/ci/test_pq_authority_effect_register.py\n',
                        '    python3 scripts/ci/pq_authority_effect_register.py\n',
                        "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_root_recovery_policy_v1.py' -v\n"):
            for replacement in ('', '    true # omitted lifetime budget check\n', command * 2):
                with self.subTest(command=command, replacement=replacement):
                    self.rejected(path, command, replacement)
            original = (self.root / path).read_text()
            changed = original.replace(command, '').replace(
                '  fuzz-smoke)\n', '  fuzz-smoke)\n' + command)
            self.rejected(path, original, changed)

    def test_one_zero_native_execution_cannot_be_removed_skipped_or_replaced(self):
        for replacement in ['', ONE_ZERO_RUN_STEP.replace('        if: always()\n', ''),
                            ONE_ZERO_RUN_STEP.replace('run: env -u CARGO_INCREMENTAL python3', 'run: true # python3'),
                            ONE_ZERO_RUN_STEP.replace('env -u CARGO_INCREMENTAL python3', 'python3'),
                            ONE_ZERO_RUN_STEP.replace('env -u CARGO_INCREMENTAL python3',
                                                      'env -u CARGO_INCREMENTAL -u RUSTFLAGS python3'),
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

    def test_mandatory_units_requires_complete_current_native_execution(self):
        for replacement in ['', '    true # omitted complete MU1 checks\n',
                            MANDATORY_UNITS_NATIVE.replace('realpath -e', 'printf %s'),
                            MANDATORY_UNITS_NATIVE.replace('MU1_NATIVE_WORK=', 'OMITTED_WORK='),
                            MANDATORY_UNITS_NATIVE.replace('MU1_NATIVE_PREPARED=', 'OMITTED_PREPARED='),
                            MANDATORY_UNITS_NATIVE.replace('mandatory_units_tests.py -v',
                                                          'mandatory_units_tests.py QueryCertificateTests -v'),
                            MANDATORY_UNITS_NATIVE * 2]:
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', MANDATORY_UNITS_NATIVE, replacement)
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        changed = original.replace(MANDATORY_UNITS_NATIVE, '').replace(
            '  repository-truth)\n', '  repository-truth)\n' + MANDATORY_UNITS_NATIVE)
        self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_work_native_model_controls_cannot_be_omitted_or_moved(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        for command in WORK_NATIVE_MODEL_COMMANDS:
            line = '    ' + command + '\n'
            for replacement in ['', '    true # omitted work/native model\n', line * 2]:
                with self.subTest(command=command, replacement=replacement):
                    self.rejected('scripts/ci/ci_job.sh', line, replacement)
            changed = original.replace(line, '').replace('  protocol-contract)\n',
                                                        '  protocol-contract)\n' + line)
            self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_actual_certificates_require_current_binaries_fresh_outputs_and_full_controls(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        for block in (WORK_LIFECYCLE_NATIVE, NATIVE_OWNER_SCORE_BRIDGE):
            for replacement in ('', '    true # omitted actual certificate execution\n',
                                block.replace('realpath -e', 'printf %s'),
                                block.splitlines(keepends=True)[0], block * 2,
                                block.replace('/native-owner-score-bridge', '/historical-native-owner')
                                if block == NATIVE_OWNER_SCORE_BRIDGE else
                                block.replace('/work-lifecycle"', '/historical-lifecycle"')):
                with self.subTest(block=block[:70], replacement=replacement[:100]):
                    self.rejected('scripts/ci/ci_job.sh', block, replacement)
            changed = original.replace(block, '').replace('  repository-truth)\n',
                                                          '  repository-truth)\n' + block)
            self.rejected('scripts/ci/ci_job.sh', original, changed)

    def test_lifecycle_closure_requires_current_native_execution_and_complete_journals(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        for block in (LIFECYCLE_QUERY_NATIVE, NATIVE_OWNER_JOURNAL):
            mutations = ['', '    true # omitted lifecycle closure\n', block * 2,
                         block.replace('realpath -e', 'printf %s'),
                         block.replace('/lifecycle-query"', '/historical-query"')
                         if block == LIFECYCLE_QUERY_NATIVE else
                         block.replace('/native-owner-journal', '/historical-journal')]
            if block == NATIVE_OWNER_JOURNAL:
                mutations.extend([block.replace('--test native_owner_journal\n',
                                                '--test native_owner_journal -- --ignored\n'),
                                  ''.join(block.splitlines(keepends=True)[1:]),
                                  ''.join(block.splitlines(keepends=True)[:-1])])
            for replacement in mutations:
                with self.subTest(block=block[:70], replacement=replacement[:100]):
                    self.rejected('scripts/ci/ci_job.sh', block, replacement)
            changed = original.replace(block, '').replace('  repository-truth)\n',
                                                          '  repository-truth)\n' + block)
            self.rejected('scripts/ci/ci_job.sh', original, changed)

        # CC1 verifies real ML-DSA signatures. The protocol-contract head and
        # merge lanes install the pinned wheel; repository-truth does not.
        command = CERTIFICATE_COMPOSITION_TESTS
        for replacement in ('', command * 2, '    true # omitted real CC1 signatures\n',
                            command.rstrip('\n') + ' || true\n'):
            self.rejected('scripts/ci/ci_job.sh', command, replacement)
        moved = original.replace(command, '').replace('  repository-truth)\n',
                                                       '  repository-truth)\n' + command)
        self.rejected('scripts/ci/ci_job.sh', original, moved)

    def test_native_risk_bank_requires_current_execution_and_all_raw_reconciliation(self):
        original = (self.root / 'scripts/ci/ci_job.sh').read_text()
        block = NATIVE_RISK_LEDGER
        lines = block.splitlines(keepends=True)
        mutations = ['', '    true # omitted native risk bank\n', block * 2,
                     block.replace('realpath -e', 'printf %s'),
                     block.replace('/native-risk-ledger', '/historical-risk-ledger'),
                     block.replace('NATIVE_RISK_LEDGER_RUN=', 'OMITTED_RISK_RUN='),
                     block.replace('--test native_risk_ledger\n',
                                   '--test native_risk_ledger -- --ignored\n'),
                     block.replace("test_native_risk_ledger.py' -v",
                                   "test_native_risk_ledger.py' -v || true")]
        mutations.extend(''.join(lines[:i] + lines[i + 1:]) for i in range(len(lines)))
        for replacement in mutations:
            with self.subTest(replacement=replacement[:100]):
                self.rejected('scripts/ci/ci_job.sh', block, replacement)
        moved_lane = original.replace(block, '').replace('  repository-truth)\n',
                                                        '  repository-truth)\n' + block)
        self.rejected('scripts/ci/ci_job.sh', original, moved_lane)
        before_build = original.replace(block, '').replace(NODE_EXAMPLE_BUILD,
                                                           block + NODE_EXAMPLE_BUILD)
        self.rejected('scripts/ci/ci_job.sh', original, before_build)

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
        self.rejected('scripts/ci/ci_job.sh', NODE_EXAMPLE_BUILD + NODE_POST_BUILD_CONTROLS + ACCOUNT_ARCHIVE_ORACLE,
                      ACCOUNT_ARCHIVE_ORACLE + NODE_EXAMPLE_BUILD + NODE_POST_BUILD_CONTROLS)

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

    def test_runtime_verifier_dependencies_are_pinned_in_both_truth_lanes(self):
        workflow = '.github/workflows/trnm-required-baseline.yml'
        for step in (RUNTIME_RELEASE_PYTHON, MERGE_RUNTIME_RELEASE_PYTHON):
            for replacement in ('', step * 2, step.replace('--require-hashes ', ''),
                                step.replace('--only-binary=:all: ', ''),
                                step.replace('--isolated ', ''),
                                step.replace('"$GITHUB_ENV"', '"$GITHUB_PATH"'),
                                step.replace('runtime-release-dependencies.json', 'unretained.json')):
                with self.subTest(step=step, replacement=replacement):
                    self.rejected(workflow, step, replacement)

    def test_runtime_verifier_dependency_cannot_be_unpinned_or_expand_the_install(self):
        path = 'scripts/ci/runtime-release-requirements.txt'
        for before, after in (('packaging==26.3', 'packaging>=25.0'),
                ('d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c', '0' * 64),
                ('packaging==26.3', 'torch==2.9.1\npackaging==26.3')):
            with self.subTest(before=before, after=after):
                self.rejected(path, before, after)

    def test_runtime_verifier_controls_keep_the_configured_interpreter(self):
        for replacement in ('', RUNTIME_RELEASE_COMMAND * 2,
                            '    python3 scripts/test_llm_runtime_release.py\n'):
            with self.subTest(replacement=replacement):
                self.rejected('scripts/ci/ci_job.sh', RUNTIME_RELEASE_COMMAND, replacement)

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

    def test_workspace_stdout_capture_is_mandatory_fresh_and_failure_preserving(self):
        lines = [line + '\n' for line in MODEL_OBSERVATION_BLOCK.splitlines()
                 if 'workspace-tests.log' in line]
        self.assertEqual(len(lines), 3)
        for line in lines:
            for replacement in ['', line * 2, line.replace('workspace-tests.log', 'old-workspace.log')]:
                with self.subTest(line=line, replacement=replacement):
                    self.rejected('scripts/ci/ci_job.sh', line, replacement)
        self.rejected('scripts/ci/ci_job.sh', lines[-1], lines[-1].replace('2>&1 | tee ', '2>&1 || tee '))

    def test_workspace_capture_executes_real_shell_and_retains_failure_output(self):
        # Actual shell processes with an explicitly synthetic cargo command,
        # not a native Rust or complete-workspace execution claim.
        block = '\n'.join(line for line in MODEL_OBSERVATION_BLOCK.splitlines()
                          if 'workspace-tests.log' in line) + '\n'
        with tempfile.TemporaryDirectory(prefix='workspace-capture-') as directory:
            root = Path(directory) / 'receipt with spaces'
            root.mkdir()
            env = {'PATH': '/usr/bin:/bin', 'TRNM_TEST_RECEIPT': str(root)}
            prelude = 'set -euo pipefail\ntrnm_model_receipt_root="$TRNM_TEST_RECEIPT"\n'
            failed = subprocess.run(['bash', '-c', prelude +
                "cargo() { printf '%s\n' 'synthetic stdout'; printf '%s\n' 'synthetic stderr' >&2; return 7; }\n" +
                block + 'touch "$TRNM_TEST_RECEIPT/incorrect-success"\n'], env=env,
                capture_output=True, text=True, timeout=10)
            self.assertEqual(failed.returncode, 7, failed.stderr)
            log = root / 'workspace-tests.log'
            self.assertIn('synthetic stdout', log.read_text())
            self.assertIn('synthetic stderr', log.read_text())
            self.assertFalse((root / 'incorrect-success').exists())
            before = log.read_bytes()
            stale = subprocess.run(['bash', '-c', prelude +
                'cargo() { touch "$TRNM_TEST_RECEIPT/incorrect-start"; }\n' + block],
                env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(stale.returncode, 0)
            self.assertEqual(log.read_bytes(), before)
            self.assertFalse((root / 'incorrect-start').exists())
            log.unlink()
            sink_failure = subprocess.run(['bash', '-c', prelude +
                'cargo() { return 0; }\ntee() { return 9; }\n' + block],
                env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(sink_failure.returncode, 9)

    def test_full_capacity_and_account_verification_execute_exact_release_tests_sequentially(self):
        path = 'scripts/ci/ci_job.sh'
        commands = [line + '\n' for line in NATIVE_RELEASE_BLOCK.splitlines() if ' cargo test ' in line]
        self.assertEqual(len(commands), 4)
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
        self.rejected(path, commands[-1], commands[-1].replace('TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY=', 'WRONG_OUTPUT='))
        self.rejected(path, commands[-1], commands[-1].replace('/native-account-verification-cost"', '/old-cost"'))
        swapped = NATIVE_RELEASE_BLOCK.replace(commands[0], 'RELEASE_CONTROL_PLACEHOLDER\n')
        swapped = swapped.replace(commands[1], commands[0]).replace('RELEASE_CONTROL_PLACEHOLDER\n', commands[1])
        self.rejected(path, NATIVE_RELEASE_BLOCK, swapped)
        self.rejected(path, NATIVE_RELEASE_BLOCK, NATIVE_RELEASE_BLOCK * 2)

    def test_release_test_execution_checks_cannot_be_removed_relabelled_or_reordered(self):
        checks = [line for line in NATIVE_RELEASE_BLOCK.splitlines(keepends=True)
                  if 'python3 scripts/ci/check_required_native_test.py ' in line]
        self.assertEqual(len(checks), 4)
        for line in checks:
            for replacement in ['', line.replace('python3 ', 'true # python3 '), line * 2,
                                line.replace(' --test ', ' --test other::'),
                                line.replace('/native-', '/previous-native-')]:
                with self.subTest(line=line, replacement=replacement):
                    self.rejected('scripts/ci/ci_job.sh', line, replacement)
            previous = NATIVE_RELEASE_BLOCK.split(line)[0].splitlines(keepends=True)[-1]
            self.rejected('scripts/ci/ci_job.sh', previous + line, line + previous)

    def test_release_control_paths_cannot_reuse_or_overwrite_prior_observations(self):
        for line in NATIVE_RELEASE_BLOCK.splitlines(keepends=True):
            if 'test ! -e ' in line or 'test ! -L ' in line:
                with self.subTest(line=line):
                    self.rejected('scripts/ci/ci_job.sh', line, '')

    def test_release_control_pipeline_keeps_actual_shell_failure_and_output(self):
        # Exercise the exact shell block using an explicitly synthetic failing
        # cargo function. This checks pipeline failure retention, not a Rust run.
        with tempfile.TemporaryDirectory(prefix='trnm-release-pipeline-') as temporary:
            for failed_case in ['capacity', 'growth-v2', 'account']:
                root = Path(temporary) / ('receipt with spaces ' + failed_case)
                harness = '''set -euo pipefail
cargo() {
  case "$*" in
    *native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover*)
      printf '%s\\n' 'synthetic capacity stdout'
      printf '%s\\n' 'synthetic capacity stderr' >&2
      if test "$TRNM_TEST_FAILURE" = capacity; then return 7; fi
      printf '%s\\n' 'running 1 test' 'test account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover ... ok' 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s' ;;
    *native_growth_reference_65537_signed_accounts_and_cold_reopen*)
      synthetic_growth_native ;;
    *native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen*)
      printf '%s\\n' 'synthetic bounded-growth stdout'
      printf '%s\\n' 'synthetic bounded-growth stderr' >&2
      if test "$TRNM_TEST_FAILURE" = growth-v2; then return 11; fi
      synthetic_growth_v2_native ;;
    *native_complete_account_verification_cost*)
      test "$TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY" = "$TRNM_CI_RECEIPT_DIR/native-account-verification-cost"
      printf '%s\\n' 'synthetic account stdout'
      printf '%s\\n' 'synthetic account stderr' >&2
      return 9 ;;
    *) return 97 ;;
  esac
}
'''
                result = subprocess.run(['bash', '-c', SYNTHETIC_GROWTH_PIPELINE + harness + NATIVE_RELEASE_BLOCK], cwd=self.root,
                                        env={'PATH': '/usr/bin:/bin', 'TRNM_CI_RECEIPT_DIR': str(root),
                                             'TRNM_TEST_FAILURE': failed_case},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, {'capacity': 7, 'growth-v2': 11, 'account': 9}[failed_case], result.stderr)
                self.assertIn('synthetic capacity stdout', (root / 'native-capacity-release.log').read_text())
                self.assertIn('synthetic capacity stderr', (root / 'native-capacity-release.log').read_text())
                account = root / 'native-account-verification-cost.log'
                if failed_case in ['capacity', 'growth-v2']:
                    self.assertFalse(account.exists())
                else:
                    self.assertIn('synthetic account stdout', account.read_text())
                    self.assertIn('synthetic account stderr', account.read_text())
                if failed_case != 'capacity':
                    growth = root / 'native-growth-v2-release.log'
                    self.assertIn('synthetic bounded-growth stdout', growth.read_text())
                    self.assertIn('synthetic bounded-growth stderr', growth.read_text())

    def test_release_pipeline_rejects_successful_zero_ignored_wrong_or_incomplete_runs(self):
        # Synthetic libtest transcripts test the real shell/checker integration,
        # not the native capacity or account algorithms.
        harness = r'''set -euo pipefail
cargo() {
  case "$*" in
    *native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover*)
      stage=capacity
      name=account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover ;;
    *native_growth_reference_65537_signed_accounts_and_cold_reopen*)
      stage=growth
      name=store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen
      test "$TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY" = "$TRNM_CI_RECEIPT_DIR/native-growth-reference"
      mkdir "$TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY" ;;
    *native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen*)
      stage=growth-v2
      name=store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen
      test "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR" = "$TRNM_CI_RECEIPT_DIR/native-growth-v2"
      mkdir "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR"
      printf '%s\n' '{"scope":"synthetic shell control only"}' > "$TRNM_NATIVE_GROWTH_V2_EXPORT_DIR/native.json" ;;
    *native_complete_account_verification_cost*)
      stage=account
      name=account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost ;;
    *) return 97 ;;
  esac
  printf '%s\n' "$stage" >> "$TRNM_TEST_CALLS"
  mode=pass
  if test "$stage" = "$TRNM_TEST_STAGE"; then mode="$TRNM_TEST_MODE"; fi
  if test "$mode" = zero; then
    printf '%s\n' 'running 0 tests' 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s'
    return 0
  fi
  if test "$mode" = wrong; then name=wrong::test; fi
  printf '%s\n' 'running 1 test'
  printf 'test %s ... ok\n' "$name"
  if test "$mode" = incomplete; then return 0; fi
  if test "$mode" = ignored; then
    printf '%s\n' 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out; finished in 0.00s'
  else
    printf '%s\n' 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s'
  fi
  if test "$mode" = nonzero; then return 23; fi
  return 0
}
'''
        with tempfile.TemporaryDirectory(prefix='trnm-release-outcomes-') as temporary:
            stages = ['capacity', 'growth', 'growth-v2', 'account']
            for stage in stages:
                for mode in ['pass', 'zero', 'ignored', 'wrong', 'incomplete', 'nonzero']:
                    with self.subTest(stage=stage, mode=mode):
                        output = Path(temporary) / f'{stage} {mode}'
                        calls = Path(temporary) / f'{stage}-{mode}.calls'
                        result = subprocess.run(['bash', '-c', SYNTHETIC_GROWTH_PIPELINE + harness + NATIVE_RELEASE_BLOCK],
                            cwd=self.root, env={'PATH': '/usr/bin:/bin',
                                'TRNM_CI_RECEIPT_DIR': str(output), 'TRNM_TEST_CALLS': str(calls),
                                'TRNM_TEST_STAGE': stage, 'TRNM_TEST_MODE': mode},
                            capture_output=True, text=True, timeout=10)
                        expected = 0 if mode == 'pass' else 23 if mode == 'nonzero' else 1
                        self.assertEqual(result.returncode, expected, result.stderr)
                        expected_calls = stages if mode == 'pass' else stages[:stages.index(stage) + 1]
                        self.assertEqual(calls.read_text().splitlines(), expected_calls)
                        self.assertTrue((output / 'native-capacity-release.log').is_file())
                        self.assertEqual((output / 'native-account-verification-cost.log').exists(),
                                         len(expected_calls) == 4)

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
        command = '      ' + RUST_ALL_TARGETS + ' 2>&1 | tee "$trnm_model_receipt_root/workspace-tests.log"\n'
        self.rejected('scripts/ci/ci_job.sh', command, '      true\n')
        self.rejected('scripts/ci/ci_job.sh', command, '      if false; then\n' + command + '      fi\n')
        self.rejected('scripts/ci/ci_job.sh', RUST_DOCS, '    ' + RUST_ALL_TARGETS + '\n' + RUST_DOCS)

    def test_merge_lane_cannot_test_head_instead(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '      TRNM_EXPECTED_SOURCE_SHA: ${{ github.sha }}',
                      '      TRNM_EXPECTED_SOURCE_SHA: ${{ github.event.pull_request.head.sha }}')

    def test_merge_lane_requires_all_actual_lanes(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      'lane: [repository-truth, protocol-contract, fuzz-smoke, external-evidence-contract]',
                      'lane: [repository-truth]')

    def test_merge_identity_is_not_itself_an_execution_pass(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      'run: bash scripts/ci/ci_job.sh "${{ matrix.lane }}"',
                      'run: python3 scripts/ci/check_repository.py')

    def test_required_rust_fanins_cannot_skip_ignore_or_invent_shards(self):
        path = '.github/workflows/trnm-required-baseline.yml'
        for worker in ['rust-baseline-shards', 'prospective-rust-shards']:
            for before, after in [
                ('    needs: ' + worker + '\n', ''),
                ('TRNM_RUST_SHARD_RESULT: ${{ needs.' + worker + '.result }}', 'TRNM_RUST_SHARD_RESULT: success')]:
                with self.subTest(before=before):
                    self.rejected(path, before, after)
        for before, after in [
            ('    if: always()\n    runs-on: ubuntu-24.04\n    timeout-minutes: 180',
             '    if: success()\n    runs-on: ubuntu-24.04\n    timeout-minutes: 180'),
            ("${{ always() && github.event_name == 'pull_request' }}", "github.event_name == 'pull_request'"),
            ('shard: [runtime, quality]', 'shard: [runtime]'),
            ('name: prospective-merge (rust-baseline)', 'name: unrelated-rust'),
            ('      - name: Run retained Rust shard\n        run:', '      - name: Run retained Rust shard\n        if: false\n        run:'),
            ('--dependency-result "$TRNM_RUST_SHARD_RESULT"', '--dependency-result success'),
            ('          path: |\n            ${{ runner.temp }}/ci-observations/rust-shard.json\n            ${{ runner.temp }}/ci-observations/rust-shard.sh\n',
             '          path: ${{ runner.temp }}/ci-observations/\n'),
            ('rust-shard-head-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}-*', 'rust-shard-head-*'),
            ('rust-shard-prospective-merge-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_attempt }}-*', 'rust-shard-prospective-merge-*')]:
            with self.subTest(before=before):
                self.rejected(path, before, after)

    def test_failure_cannot_be_marked_ignorable(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '  fuzz-smoke:\n', '  fuzz-smoke:\n    continue-on-error: true\n')

    def test_arm_label_cannot_be_replaced_with_an_x64_runner(self):
        self.rejected('.github/workflows/trnm-required-baseline.yml',
                      '            runner: ubuntu-24.04-arm', '            runner: ubuntu-24.04')

    def test_architecture_label_is_not_native_cost_execution(self):
        command = 'run: env -u CARGO_INCREMENTAL python3 scripts/ci/run_cross_arch_cost.py --arch "${{ matrix.arch }}"'
        for replacement in ('run: python3 scripts/ci/check_ci_contract.py',
                            command.replace('env -u CARGO_INCREMENTAL python3', 'python3'),
                            command.replace('env -u CARGO_INCREMENTAL python3',
                                            'env -u CARGO_INCREMENTAL -u RUSTFLAGS python3')):
            with self.subTest(replacement=replacement):
                self.rejected('.github/workflows/trnm-required-baseline.yml', command, replacement)

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

    def test_fuzz_cannot_omit_required_local_serialization_edges(self):
        path = self.root / 'tests/fuzz/Cargo.lock'
        text = path.read_text()
        start = text.index('name = "trnm-data-availability"')
        end = text.index('[[package]]', start)
        package = text[start:end]
        for dependency in ('serde', 'serde_json'):
            with self.subTest(dependency=dependency):
                changed = package.replace(' "' + dependency + '",\n', '')
                self.assertNotEqual(package, changed)
                self.rejected('tests/fuzz/Cargo.lock', package, changed)

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


class W1PostwinLaneTests(unittest.TestCase):
    """Executable CI contracts, not a substitute proof or provider success."""

    def setUp(self):
        self.script = (ROOT / "scripts/ci/ci_job.sh").read_text()
        self.workflow = (ROOT / ".github/workflows/pon-w1-transparent-profile.yml").read_text()
        self.required = {"repository-truth", "protocol-contract", "fuzz-smoke",
                         "rust-baseline", "external-evidence-contract"}

    def lane_check(self, text):
        check_independent_conformance(text, self.required)

    def workflow_check(self, text):
        from check_ci_contract import check_w1_postwin_workflow
        check_w1_postwin_workflow(text)

    def step(self, name):
        import re
        blocks = re.findall(r"(?ms)^      - name: .*?(?=^      - name: |\Z)", self.workflow)
        rows = [row for row in blocks if "\n        id: " + name + "\n" in row]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def commands(self):
        # Independent literal inventory: do not import the checker's roster.
        return (
            'python3 -m unittest discover -s scripts/ci -p test_w1_cancellation_handoff.py -v 2>&1 | tee "$w1_contract_out/cancellation-handoff.log"',
            'python3 -m unittest discover -s scripts/ci -p test_w1_coordinator_contract.py -v 2>&1 | tee "$w1_contract_out/coordinator-contract.log"',
            'python3 -m unittest discover -s scripts -p test_kaggle_generation_contract_v2.py -v 2>&1 | tee "$w1_contract_out/provider-contract.log"',
            'python3 -m unittest discover -s scripts -p test_w1_generation_target_v2.py -v 2>&1 | tee "$w1_contract_out/generation-target.log"',
            'python3 -m unittest discover -s scripts -p test_w1_owner_cancellation_v1.py -v 2>&1 | tee "$w1_contract_out/owner-cancellation.log"',
            'python3 -m unittest discover -s scripts/ci -p test_w1_kaggle_source_builder.py -v 2>&1 | tee "$w1_contract_out/source-builder.log"',
            'python3 -m unittest discover -s scripts -p test_w1_owned_generation_runtime_v2.py -v 2>&1 | tee "$w1_contract_out/owned-runtime-reader.log"',
            'python3 -m unittest discover -s scripts/ci -p test_w1_kaggle_worker_contract.py -v 2>&1 | tee "$w1_contract_out/kaggle-worker-contract.log"',
            'python3 -m unittest discover -s scripts/ci -p test_w1_postwin_identity.py -v 2>&1 | tee "$w1_contract_out/winner-identity.log"',
            'python3 -m unittest discover -s scripts/ci -p test_w1_deployment_evidence_binding.py -v 2>&1 | tee "$w1_contract_out/deployment-evidence-binding.log"',
            'python3 -m unittest discover -s scripts/ci -p test_w1_deployment_comparison_audit.py -v 2>&1 | tee "$w1_contract_out/deployment-comparison-audit.log"',
            'python3 scripts/test_w1_owned_process_collector_v1.py -v 2>&1 | tee "$w1_contract_out/owned-process-collector.log"',
        )

    def test_actual_postwin_lanes_retain_real_controls(self):
        self.lane_check(self.script)
        self.workflow_check(self.workflow)

    def test_required_postwin_commands_cannot_be_missing_stubbed_or_swallowed(self):
        for command in self.commands():
            line = "      " + command + "\n"
            self.assertEqual(self.script.count(line), 1)
            replacements = (
                "", line + line, "      # " + command + "\n",
                "      true # " + command + "\n",
                "      " + command + " || true\n",
                "      if false; then\n" + line + "      fi\n",
                "      if " + command + "; then :; fi\n",
            )
            for replacement in replacements:
                with self.subTest(command=command, replacement=replacement):
                    with self.assertRaises(ValueError):
                        self.lane_check(self.script.replace(line, replacement, 1))

    def test_required_postwin_commands_cannot_change_or_duplicate_lane(self):
        for command in self.commands():
            line = "      " + command + "\n"
            for remove_original in (False, True):
                changed = self.script.replace(line, "", 1) if remove_original else self.script
                changed = changed.replace("  fuzz-smoke)\n", "  fuzz-smoke)\n" + line, 1)
                with self.subTest(command=command, moved=remove_original):
                    with self.assertRaises(ValueError):
                        self.lane_check(changed)

    def test_postwin_count_and_original_budget_controls_cannot_be_softened(self):
        mutations = (
            ('("cancellation-handoff", 22)', '("cancellation-handoff", 0)'),
            ('("coordinator-contract", 20)', '("coordinator-contract", 1)'),
            ('("provider-contract", 11)', '("provider-contract", 8)'),
            ('("generation-target", 13)', '("generation-target", 0)'),
            ('("generation-target", 13)', '("generation-target", 7)'),
            ('("generation-target", 13)', '("generation-target", 4)'),
            ('("owner-cancellation", 8)', '("owner-cancellation", 0)'),
            ('("owner-cancellation", 8)', '("owner-cancellation", 7)'),
            ('("owner-cancellation", 8)', '("owner-cancellation", 5)'),
            ('("source-builder", 8)', '("source-builder", 0)'),
            ('("owned-runtime-reader", 7)', '("owned-runtime-reader", 0)'),
            ('("owned-runtime-reader", 7)', '("owned-runtime-reader", 5)'),
            ('("kaggle-worker-contract", 12)', '("kaggle-worker-contract", 0)'),
            ('("winner-identity", 4)', '("winner-identity", 0)'),
            ('("deployment-evidence-binding", 12)', '("deployment-evidence-binding", 0)'),
            ('("deployment-evidence-binding", 12)', '("deployment-evidence-binding", 9)'),
            ('("deployment-comparison-audit", 20)', '("deployment-comparison-audit", 0)'),
            ('("deployment-comparison-audit", 20)', '("deployment-comparison-audit", 10)'),
            ('("owned-process-collector", 14)', '("owned-process-collector", 0)'),
            ('("owned-process-collector", 14)', '("owned-process-collector", 13)'),
            (' or "skipped=" in text', ''),
            ('      export TMPDIR="$w1_contract_tmp"\n', ''),
            ('      trap \'rm -rf -- "$w1_contract_tmp"\' EXIT\n', ''),
            ('    (\n      w1_contract_out=', '    if false; then\n    (\n      w1_contract_out='),
            ('      export PYTHONDONTWRITEBYTECODE=1\n',
             '      export PYTHONDONTWRITEBYTECODE=1\n      set +e\n'),
        )
        for before, after in mutations:
            self.assertIn(before, self.script)
            with self.subTest(before=before):
                with self.assertRaises(ValueError):
                    self.lane_check(self.script.replace(before, after, 1))

    def test_real_receiver_step_cannot_be_missing_duplicated_or_bypassed(self):
        block = self.step("real_receiver_controls")
        for replacement in (
            "", block + block,
            block.replace("        if: always() && steps.source.outcome == 'success' && steps.verifier_v2.outcome == 'success'\n",
                          "        if: false\n"),
            block.replace("          python3 scripts/ci/test_w1_receiver_real.py",
                          "          true # python3 scripts/ci/test_w1_receiver_real.py"),
            block.replace(' | tee "$W1_PROFILE_OUT/real-receiver-controls.log"',
                          ' | tee "$W1_PROFILE_OUT/real-receiver-controls.log" || true'),
            block.replace("          set -euo pipefail\n", "          set +e\n"),
        ):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(block, replacement, 1))

    def test_real_receiver_requires_all_exact_v2_inputs_and_fresh_output(self):
        block = self.step("real_receiver_controls")
        mutations = (
            ('--verifier "$w1_v2_verifier"', ''),
            ('--verifier-sha256 "$w1_v2_verifier_sha"', ''),
            ('--receipt "$w1_v2_fixture/succinct.bin"', ''),
            ('--input "$w1_v2_fixture/input.bin"', ''),
            ('--header "$w1_v2_fixture/header.bin"', ''),
            ('--expected-artifacts "$w1_v2_fixture/expected-artifacts.bin"', ''),
            ('evidence/pon-w1-full-v2-20261105', 'evidence/pon-w1-complete-succinct-20261028/full-proof'),
            ('--out "$W1_PROFILE_OUT/real-receiver-controls"', '--out /tmp/retained-receiver-success'),
            ('257014, "6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee"',
             '257014, "' + "0" * 64 + '"'),
            ('counts = {"tests_run": 11,', 'counts = {"tests_run": 0,'),
            ('counts = {"tests_run": 11,', 'counts = {"tests_run": 7,'),
            ('"skipped": 0', '"skipped": 7'),
            ('"fresh_proof_generations": 0', '"fresh_proof_generations": 1'),
            ('report.get("actual_complete_receipt_used") is not True', 'False'),
        )
        for before, after in mutations:
            self.assertIn(before, block)
            with self.subTest(before=before):
                changed = block.replace(before, after, 1)
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(block, changed, 1))

    def test_real_receiver_requires_current_successful_release_build(self):
        verifier, receiver = self.step("verifier_v2"), self.step("real_receiver_controls")
        self.assertIn(verifier + receiver, self.workflow)
        with self.assertRaises(ValueError):
            self.workflow_check(self.workflow.replace(verifier + receiver, receiver + verifier, 1))
        for before, after in (
            ('cargo +1.95.0 build --locked --release --manifest-path "$w1_manifest"',
             'true # cargo +1.95.0 build --locked --release --manifest-path "$w1_manifest"'),
            ('cp "$CARGO_TARGET_DIR/release/w1-verify-v2"', 'cp /tmp/old-verifier'),
            ('-- -D warnings', '-- -A warnings'),
        ):
            self.assertIn(before, verifier)
            with self.subTest(before=before):
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(verifier, verifier.replace(before, after, 1), 1))

    def test_postwin_staged_count_and_source_identity_cannot_be_softened(self):
        for name, before, after in (
            ("staged_tests", "counts != ['32']", "counts != ['0']"),
            ("staged_tests", " or 'skipped=' in text", ""),
            ("source", "python3 scripts/ci/verify_ci_source.py", "true # python3 scripts/ci/verify_ci_source.py"),
            ("source_after", "python3 scripts/ci/verify_ci_source.py", "true # python3 scripts/ci/verify_ci_source.py"),
            ("toolchain", "rustup toolchain install 1.95.0", "true # rustup toolchain install 1.95.0"),
        ):
            block = self.step(name)
            self.assertIn(before, block)
            with self.subTest(name=name, before=before):
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(block, block.replace(before, after, 1), 1))

    def test_postwin_controls_keep_head_merge_matrix_and_read_only_scope(self):
        for before, after in (
            ("        source: [head, prospective-merge]", "        source: [head]"),
            ("    timeout-minutes: 60", "    timeout-minutes: 0"),
            ("  contents: read", "  contents: write"),
            ("  cancel-in-progress: false", "  cancel-in-progress: true"),
            ("      - evidence/pon-w1-full-v2-20261105/**\n", ""),
            ("      - evidence/pon-w1-fresh-runtime-20261107/**\n", ""),
            ("      - scripts/audit_w1_deployment_comparison.py\n", ""),
            ("      - scripts/w1_owned_process_collector_v1.py\n", ""),
            ("      - scripts/test_w1_owned_process_collector_v1.py\n", ""),
            ("      - scripts/w1_owner_cancellation_v1.py\n", ""),
            ("      - scripts/test_w1_owner_cancellation_v1.py\n", ""),
        ):
            self.assertIn(before, self.workflow)
            with self.subTest(before=before):
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(before, after, 1))

    def test_repository_contracts_cannot_move_into_optional_profile(self):
        for command in self.commands():
            inserted = ('      - name: Wrong duplicate required lane\n'
                        '        run: ' + command + '\n')
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow + inserted)


    def test_new_named_mapper_and_v2_gate_controls_cannot_be_reduced(self):
        for name, count, command in (
            ('mapper_tests', 15, 'test_w1_profile_source_map.py'),
            ('v2_gate_tests', 23, 'test_w1_v2_controls_gate.py'),
        ):
            block = self.step(name)
            mutations = (
                (f"!= ['{count}']", "!= ['0']"),
                ('sorted(rows) != required', 'False'),
                ("!= ['OK']", "!= ['OK (skipped=1)']"),
                ('python3 -m unittest discover', 'true # python3 -m unittest discover'),
                ("if: always() && steps.source.outcome == 'success'", 'if: false'),
            )
            for before, after in mutations:
                with self.subTest(step=name, before=before):
                    self.assertIn(before, block)
                    with self.assertRaises(ValueError):
                        self.workflow_check(self.workflow.replace(block, block.replace(before, after, 1), 1))
            for replacement in ('', block + block):
                with self.subTest(step=name, replacement=replacement[:40]), self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(block, replacement, 1))
            self.assertIn(command, block)

    def test_verifier_keeps_all_three_exact_tests_and_independent_build(self):
        block = self.step('verifier_v2')
        mutations = (
            ('tests::expected_artifacts_are_exact_and_never_derived_from_receipt', 'tests::unreviewed_artifacts'),
            ('tests::historical_full_receipt_cannot_satisfy_v2_statement', 'tests::unreviewed_historical'),
            ('tests::saved_full_v2_receipt_verifies_with_independent_artifacts', 'tests::unreviewed_saved_proof'),
            ('len(rows) != 3', 'len(rows) < 2'),
            ('{name for name, _ in rows} != expected', 'not expected.issubset({name for name, _ in rows})'),
            ("!= ['3']", "!= ['0']"),
            ('0 filtered out;', '1 filtered out;'),
            ('-- --format=pretty --test-threads=1', '-- saved_full_v2_receipt --format=pretty --test-threads=1'),
            ("packages.intersection({'risc0-build'", "packages.intersection({'unrelated-build'"),
            ('cargo +1.95.0 metadata --locked', 'true # cargo +1.95.0 metadata --locked'),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, block)
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(block, block.replace(before, after, 1), 1))

    def test_saved_58_suite_keeps_all_original_inputs_readback_and_four_minutes(self):
        block = self.step('receipt_controls_v2')
        mutations = (
            ('        timeout-minutes: 4\n', ''),
            ('        timeout-minutes: 4\n', '        timeout-minutes: 5\n'),
            ('RAYON_NUM_THREADS=8', 'RAYON_NUM_THREADS=1'),
            ('--verifier "$w1_verifier"', '--verifier /tmp/old-verifier'),
            ('--receipt "$w1_proof_dir/succinct.bin"', '--receipt /tmp/other-receipt'),
            ('--header "$w1_proof_dir/header.bin"', ''),
            ('--expected-artifacts "$w1_proof_dir/expected-artifacts.bin"', ''),
            ('--out "$W1_PROFILE_OUT/v2-controls"', '--out /tmp/prior-controls'),
            ('python3 scripts/ci/w1_v2_controls_gate.py', 'true # python3 scripts/ci/w1_v2_controls_gate.py'),
            ('python3 scripts/w1_v2_receipt_controls.py', 'true # python3 scripts/w1_v2_receipt_controls.py'),
            ('          set -euo pipefail\n', '          set +e\n'),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, block)
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(block, block.replace(before, after, 1), 1))
        for replacement in ('', block + block, block.replace('        shell: bash\n', '        if: false\n        shell: bash\n', 1)):
            with self.subTest(replacement=replacement[:40]), self.assertRaises(ValueError):
                self.workflow_check(self.workflow.replace(block, replacement, 1))

    def test_both_receiver_suites_and_final_outcome_block_are_mandatory(self):
        marker = '      - name: Record completed, failed and skipped observations\n'
        footer = marker + self.workflow.split(marker, 1)[1].split('\n      - ', 1)[0] + '\n'
        for before, after in (
            ("'real_receiver_controls', ", ''),
            ("'receipt_controls_v2', ", ''),
            (".get('outcome') != 'success'", "False"),
            ('          if incomplete:\n', '          if False:\n'),
            ("'production_qualified': False", "'production_qualified': True"),
            ('        if: always()\n', '        if: success()\n'),
        ):
            with self.subTest(before=before):
                self.assertIn(before, footer)
                with self.assertRaises(ValueError):
                    self.workflow_check(self.workflow.replace(footer, footer.replace(before, after, 1), 1))
        for replacement in ('', footer + footer):
            with self.subTest(replacement=replacement[:40]), self.assertRaises(ValueError):
                self.workflow_check(self.workflow.replace(footer, replacement, 1))
        verifier, real, saved = (self.step(name) for name in ('verifier_v2', 'real_receiver_controls', 'receipt_controls_v2'))
        for before, after in ((verifier + real, real + verifier), (real + saved, saved + real)):
            self.assertIn(before, self.workflow)
            with self.assertRaises(ValueError):
                self.workflow_check(self.workflow.replace(before, after, 1))

    def test_actual_footer_refuses_each_failed_skipped_or_missing_original_stage(self):
        marker = '      - name: Record completed, failed and skipped observations\n'
        footer = self.workflow.split(marker, 1)[1].split('\n      - ', 1)[0]
        code = textwrap.dedent(footer.split("<<'PY'\n", 1)[1].split('\n          PY', 1)[0]) + '\n'
        required = ('checkout', 'source', 'toolchain', 'source_controls', 'observer_tests',
                    'mapper_tests', 'v2_gate_tests', 'staged_tests', 'budget_tests', 'native', 'hardened',
                    'verifier_v2', 'real_receiver_controls', 'receipt_controls_v2', 'component_budget', 'source_map',
                    'profile', 'receipt_controls', 'comparison', 'source_after')
        good = {name: {'outcome': 'success', 'conclusion': 'success'} for name in required}
        with tempfile.TemporaryDirectory(prefix='w1-final-outcome-') as directory:
            directory = Path(directory)
            def run(index, steps):
                path = directory / (str(index) + '.json')
                env = dict(os.environ, W1_PROFILE_STEP_RESULTS=json.dumps(steps),
                           SOURCE_KIND='head', EXPECTED_SOURCE='1' * 40)
                result = subprocess.run([sys.executable, '-B', '-c', code, str(path)], env=env,
                                        capture_output=True, text=True)
                return result, json.loads(path.read_text())
            result, report = run('positive', good)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIs(report['production_qualified'], False)
            for name in required:
                for state in ('failure', 'skipped', 'missing'):
                    with self.subTest(stage=name, state=state):
                        steps = {key: dict(value) for key, value in good.items()}
                        if state == 'missing':
                            steps.pop(name)
                        else:
                            steps[name]['outcome'] = state
                        result, retained = run(name + '-' + state, steps)
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn(name, result.stderr)
                        self.assertEqual(retained['steps'], steps)
                        self.assertIs(retained['quantum_soundness_qualified'], False)

    def test_added_source_snapshot_triggers_cannot_be_removed(self):
        for path in ('evidence/pon-w1-stark-review-20261106/**', 'evidence/pon-w1-source-snapshot-20261106/**'):
            before = '      - ' + path + '\n'
            self.assertIn(before, self.workflow)
            with self.assertRaises(ValueError):
                self.workflow_check(self.workflow.replace(before, '', 1))




class MergedQualificationLaneTests(unittest.TestCase):
    """Independent source-contract controls; these do not execute native lanes."""

    # Keep these literals independent from every checker's roster and prefix.
    GROUPS = {
        'credit': ('repository-truth', '    bash scripts/project-preflight.sh --audit\n', (
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_envelope_contract.py' -v\n",
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_normalized_search_cost.py' -v\n",
        ), '    python3 scripts/ci/test_project_boundary.py\n'),
        'pq_effect_root': ('repository-truth', '    python3 scripts/ci/pq_lifetime_budget.py\n', (
            '    python3 scripts/ci/test_pq_authority_effect_register.py\n',
            '    python3 scripts/ci/pq_authority_effect_register.py\n',
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_pq_root_recovery_policy_v1.py' -v\n",
            '    python3 formal/pon-nakamoto-v1/test_pq_root_recovery_signatures_v2.py -v\n',
            '    python3 formal/pon-nakamoto-v1/test_pq_root_effect_readback_v2.py -v\n',
            '    python3 scripts/ci/test_pq_root_dependency_register.py\n',
            '    python3 scripts/ci/pq_root_dependency_register.py\n',
            '    python3 scripts/ci/test_run_pq_root_native_v3.py\n',
            '    python3 scripts/ci/test_pq_root_custody_review_v1.py\n',
            '    python3 scripts/ci/pq_root_custody_review_v1.py\n',
            '    python3 scripts/ci/test_pq_root_custody_review_v2.py\n',
            '    python3 scripts/ci/pq_root_custody_review_v2.py\n',
            '    python3 scripts/ci/test_pq_root_migration_review_v1.py\n',
            '    python3 scripts/ci/pq_root_migration_review_v1.py\n',
            '    python3 scripts/ci/test_run_pq_root_continuation_v4.py\n',
            '    python3 scripts/ci/test_run_pq_root_witness_v5.py\n',
            '    python3 scripts/ci/test_ci_observation_process.py\n',
            '    python3 scripts/ci/test_authenticated_suite_count.py\n',
        ), '    python3 scripts/ci/test_pq_chain_claim_guard.py\n'),
        'qrom_current_source': ('repository-truth', '    python3 scripts/ci/test_pq_chain_claim_guard.py\n    # Current selected-source mapping retains the historical V1 refusal and all HOLD flags.\n', (
            '    python3 scripts/ci/test_w1_qrom_current_implementation_audit.py\n',
            '    python3 scripts/w1_qrom_current_implementation_audit.py\n',
        ), '    python3 scripts/ci/test_w1_upstream_security.py\n'),
        'upstream_security': ('repository-truth', '    python3 scripts/w1_qrom_current_implementation_audit.py\n', (
            '    python3 scripts/ci/test_w1_upstream_security.py\n',
            '    python3 scripts/ci/w1_upstream_security.py\n',
            '    python3 scripts/ci/test_pq_proof_profile_binding.py\n',
            '    python3 scripts/ci/pq_proof_profile_binding.py\n',
            '    python3 scripts/ci/test_w1_qrom_current_ci.py\n',
        ), '    # Exact field/source correspondence does not discharge STARK/QROM obligations.\n    python3 scripts/ci/test_w1_stark_field_certificates.py\n'),
        'stark_routes_and_fields': ('repository-truth', '    python3 scripts/ci/test_w1_qrom_current_ci.py\n    # Exact field/source correspondence does not discharge STARK/QROM obligations.\n', (
            '    python3 scripts/ci/test_w1_stark_field_certificates.py\n',
            '    python3 scripts/w1_stark_field_certificates.py\n',
            '    python3 scripts/ci/test_w1_stark_route_audit.py\n',
            '    python3 scripts/w1_stark_route_audit.py\n',
        ), '    # Conditional iid counting does not establish the actual transcript distribution.\n    python3 scripts/ci/test_w1_fri_ideal_sampler.py\n'),
        'conditional_sampler': ('repository-truth', '    python3 scripts/w1_stark_route_audit.py\n    # Conditional iid counting does not establish the actual transcript distribution.\n', (
            '    python3 scripts/ci/test_w1_fri_ideal_sampler.py\n',
            '    python3 scripts/w1_fri_query_replay.py --ideal-sampler-law\n',
        ), '    # Current lifetime source observation is separate from historical positive replay.\n    python3 scripts/ci/test_w1_lifetime_current_observation.py\n'),
        'lifetime_current_source': ('repository-truth', '    python3 scripts/w1_fri_query_replay.py --ideal-sampler-law\n    # Current lifetime source observation is separate from historical positive replay.\n', (
            '    python3 scripts/ci/test_w1_lifetime_current_observation.py\n',
            '    python3 scripts/w1_lifetime_current_observation.py\n',
            '    python3 scripts/ci/test_w1_qrom_closure_current_controls.py\n',
        ), "    python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v\n"),
        'posterior_policy': ('repository-truth',
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_adversarial_search.py' -v\n", (
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_posterior_policy.py' -v\n",
        ), "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_resource_clock.py' -v\n"),
        'hash_use_contract': ('repository-truth', '    python3 scripts/ci/pq_authority_surface_scan.py --summary-only\n', (
            '    python3 scripts/ci/test_hash_use_contract.py\n',
            '    python3 scripts/ci/hash_use_contract.py\n',
        ), "    python3 -m unittest discover -s scripts/ci -p 'test_pq_external_rollback_oracle.py' -v\n"),
        'failed_campaign_diagnostics': ('repository-truth',
            '    python3 scripts/ci/test_run_pon_w1_native_campaign.py\n', (
                '    python3 scripts/ci/test_read_validated_business_goodput.py\n',
                '    python3 scripts/ci/test_read_failed_native_campaign_zip.py\n',
            ), '    python3 scripts/ci/test_pon_w1_cost_matrix_reader.py\n'),
        'native_observation_guards': ('repository-truth',
            '    python3 scripts/ci/test_run_legacy_reorg_root_abba.py\n', (
                '    python3 -B scripts/ci/test_w1_factorial_native_gate.py\n',
                '    python3 -B scripts/ci/test_prepare_artifact_upload.py\n',
                '    python3 -B scripts/ci/test_cell_storage_convergence_ci.py\n',
                '    python3 -B scripts/ci/test_fresh_rejection_report.py\n',
            ), '    # These in-memory counterexamples use unchanged retained inputs, not a new hardware observation.\n'
            '    python3 scripts/ci/test_pon_w1_budget_readers.py --raw-dir evidence/pon-upgrade-implementation-20261018/native-rounds/chain-p0-native-54\n'),
        'fixed_probability': ('repository-truth',
                              "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_work_scale_contract.py' -v\n", (
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_fixed_probability_contract.py' -v\n",
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_credit_feasibility.py' -v\n",
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential.py' -v\n",
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential_independent.py' -v\n",
            '    python3 formal/pon-nakamoto-v1/fixed_probability_contract.py\n',
            '    python3 formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py --check\n',
        ), '    python3 formal/pon-nakamoto-v1/stateful_tail.py\n'),
        'joint_consensus_qualification': ('repository-truth',
            '    python3 formal/pon-nakamoto-v1/test_joint_consensus_boundaries.py -v\n', (
            '    python3 formal/pon-nakamoto-v1/joint_consensus_qualification.py --check\n',
            '    python3 formal/pon-nakamoto-v1/test_joint_consensus_qualification.py\n',
            '    python3 formal/pon-nakamoto-v1/test_dynamic_participation_v1.py\n',
            '    python3 formal/pon-nakamoto-v1/test_joint_production_tail_v1.py\n',
        ), '    python3 formal/pon-nakamoto-v1/certificate_event_coverage_tests.py -v\n'),
        'joint_resource_competition': ('repository-truth',
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_network_sim.py' -v\n", (
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_probability_sampling.py' -v\n",
            "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_joint_resource_competition_campaign.py' -v\n",
        ), "    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_candidate_check_clock.py' -v\n"),
        'system_security': ('repository-truth',
                            '    python3 scripts/ci/test_capture_chain_hepta_identity.py\n', (
            '    python3 scripts/ci/test_chain_hepta_qualification.py\n',
            '    python3 scripts/ci/test_chain_system_security.py\n',
        ), '    python3 scripts/ci/test_chain_hepta_command_binding.py\n'),
        'completion': ('external-evidence-contract', '    python3 scripts/ci/test_invariant_evidence.py\n', (
            '    python3 scripts/ci/check_completion_evidence.py --historical\n',
            '    python3 scripts/ci/test_completion_evidence.py\n',
        ), '    python3 scripts/ci/check_evaluation_bundle_evidence.py --historical\n'),
        'learning_business': ('repository-truth', '    python3 scripts/ci/test_chain_hepta_command_binding.py\n', (
            '    python3 scripts/test_cell_learning_business_economics.py\n',
            '    python3 scripts/test_cell_learning_business_join.py\n',
            '    python3 scripts/test_cell_learning_training_no_update_join.py\n',
        ), '    python3 scripts/ci/test_pon_daa_head_binding.py\n'),
    }

    def setUp(self):
        self.script = (ROOT / 'scripts/ci/ci_job.sh').read_text()
        self.required = {'repository-truth', 'protocol-contract', 'fuzz-smoke',
                         'rust-baseline', 'external-evidence-contract'}

    def checked(self, script):
        check_independent_conformance(script, self.required)

    def test_actual_merged_lanes_keep_all_original_controls(self):
        self.checked(self.script)

    def test_independent_literals_keep_original_neighbors_and_unique_commands(self):
        self.checked(self.script)
        for name, (lane, before, commands, after) in self.GROUPS.items():
            block = self.script.split('  ' + lane + ')\n', 1)[1].split('    ;;\n', 1)[0]
            with self.subTest(group=name):
                self.assertIn(before + ''.join(commands) + after, block)
                for command in commands:
                    self.assertEqual(self.script.count(command), 1)

    def reject_command_mutations(self, group):
        # A positive precondition prevents a stale checker from making every
        # negative case pass merely because the untouched lane already fails.
        self.checked(self.script)
        lane, _, commands, after = self.GROUPS[group]
        for command in commands:
            self.assertEqual(self.script.count(command), 1)
            variants = {
                'removed': self.script.replace(command, '', 1),
                'modified argv': self.script.replace(command, command.replace('python3 ', 'python3 -O ', 1), 1),
                'duplicated locally': self.script.replace(command, command * 2, 1),
                'commented out': self.script.replace(command, '    # ' + command.lstrip(), 1),
                'false branch': self.script.replace(command, '    if false; then\n' + command + '    fi\n', 1),
                'swallowed failure': self.script.replace(command, command.rstrip() + ' || true\n', 1),
                'errexit suppressed': self.script.replace(command, '    if\n' + command + '    then :; fi\n', 1),
                'backgrounded': self.script.replace(command, command.rstrip() + ' &\n', 1),
                'moved within lane': self.script.replace(command, '', 1).replace(after, after + command, 1),
                'moved to fuzz lane': self.script.replace(command, '', 1).replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command, 1),
                'duplicated in fuzz lane': self.script.replace('  fuzz-smoke)\n', '  fuzz-smoke)\n' + command, 1),
            }
            for label, changed in variants.items():
                self.assertNotEqual(changed, self.script)
                with self.subTest(group=group, lane=lane, command=command, mutation=label):
                    with self.assertRaises(ValueError):
                        self.checked(changed)

    def test_credit_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('credit')

    def test_pq_effect_root_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('pq_effect_root')

    def test_current_mapping_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('qrom_current_source')

    def test_upstream_security_controls_cannot_be_skipped_or_suppressed(self):
        self.reject_command_mutations('upstream_security')

    def test_posterior_policy_controls_cannot_be_skipped_or_suppressed(self):
        self.reject_command_mutations('posterior_policy')

    def test_hash_use_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('hash_use_contract')
    def test_stark_route_field_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('stark_routes_and_fields')

    def test_conditional_sampler_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('conditional_sampler')

    def test_current_lifetime_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('lifetime_current_source')

    def test_native_observation_guard_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('native_observation_guards')

    def test_fixed_probability_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('fixed_probability')

    def test_joint_consensus_qualification_commands_cannot_be_omitted_moved_or_skipped(self):
        self.reject_command_mutations('joint_consensus_qualification')

    def test_joint_resource_commands_cannot_be_omitted_moved_or_skipped(self):
        self.reject_command_mutations('joint_resource_competition')

    def test_completion_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('completion')

    def test_learning_business_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('learning_business')

    def test_system_security_commands_cannot_change_position_multiplicity_or_failure_policy(self):
        self.reject_command_mutations('system_security')

    def test_complete_groups_cannot_reorder_duplicate_or_hide_in_shell_conditions(self):
        self.checked(self.script)
        for name, (_, _, commands, _) in self.GROUPS.items():
            block = ''.join(commands)
            for replacement in (
                    ''.join(reversed(commands)), block + block,
                    '    if false; then\n' + block + '    fi\n',
                    '    if\n' + block + '    then :; fi\n',
                    '    {\n' + block + '    } || true\n'):
                if replacement == block:  # Reversing a one-command group changes nothing.
                    continue
                with self.subTest(group=name, replacement=replacement):
                    with self.assertRaises(ValueError):
                        self.checked(self.script.replace(block, replacement, 1))

    def test_whole_repository_and_external_lanes_cannot_suppress_failures(self):
        self.checked(self.script)
        for lane in ('repository-truth', 'external-evidence-contract'):
            marker = '  ' + lane + ')\n'
            block = self.script.split(marker, 1)[1].split('    ;;\n', 1)[0]
            for replacement in (
                    '    if false; then\n' + block + '    fi\n',
                    '    if\n' + block + '    then :; fi\n',
                    '    {\n' + block + '    } || true\n',
                    '    set +e\n' + block,
                    block + '    true\n'):
                with self.subTest(lane=lane, replacement=replacement[:80]):
                    with self.assertRaises(ValueError):
                        self.checked(self.script.replace(marker + block, marker + replacement, 1))



class CellCurrentApiReadbackTests(unittest.TestCase):
    """Exercise the actual workflow predicate using an unchanged CI observation."""

    WORKFLOW = Path(".github/workflows/pon-pq-system-continuation.yml")
    FIXTURE = Path("tests/fixtures/ci/cell-current-api-readback-v2-66b7064.log")
    OBSERVATION = Path("tests/fixtures/ci/cell-current-api-readback-v2-66b7064.json")
    ORIGINAL_SHA256 = "43059fa21c3542eff4f0c4aeb3552207847a8b483d214ce1e1514f79a4c09553"
    EXACT_CASE = ("test crates/trnm-data-availability/src/cell/pq.rs - "
                  "cell::pq::VerifiedCellPqReleaseV2 (line 364) - compile fail ... ok")
    SUMMARY = ("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
               "15 filtered out; finished in 0.04s")

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        raw = (cls.root / cls.FIXTURE).read_bytes()
        if hashlib.sha256(raw).hexdigest() != cls.ORIGINAL_SHA256:
            raise AssertionError("original compile-fail observation changed")
        cls.observed = raw.decode("utf-8")
        cls.observation = json.loads((cls.root / cls.OBSERVATION).read_bytes())
        sys.path.insert(0, str(cls.root / "scripts/ci"))
        import check_cell_current_api
        cls.reader = check_cell_current_api
        command = 'python3 scripts/ci/check_cell_current_api.py "$out/cell-current-api.log"'
        if (cls.root / cls.WORKFLOW).read_text().count(command) != 1:
            raise AssertionError("exactly one actual source-bound readback command is required")

    def observe(self, text):
        # The unchanged historical log is intentionally read at its historical
        # source line; the current CLI derives its line from the current source.
        report = self.reader.inspect(text, 364)
        return (0 if report["result"] == "PASS" else 1), report

    def assert_refused(self, text):
        status, report = self.observe(text)
        self.assertEqual(status, 1, report)
        self.assertEqual(report["result"], "FAIL", report)
        self.assertEqual(report["contract"], "cell-current-view-required")

    def test_actual_current_view_doc_observation_is_accepted(self):
        status, report = self.observe(self.observed)
        self.assertEqual(status, 0, report)
        self.assertEqual(report, {
            "contract": "cell-current-view-required",
            "diagnostic_codes": ["E0308"],
            "executed_tests": 1,
            "result": "PASS",
            "scope": "compile-fail-type-boundary-observation",
        })

    def test_old_or_wrong_exact_case_identity_is_refused(self):
        for replacement in (
            self.EXACT_CASE.replace("(line 364)", "(line 359)"),
            self.EXACT_CASE.replace("(line 364)", "(line 365)"),
            self.EXACT_CASE.replace("VerifiedCellPqReleaseV2", "VerifiedCellPqReleaseV1"),
            self.EXACT_CASE.replace("src/cell/pq.rs", "src/cell/other.rs"),
            self.EXACT_CASE.replace(" ... ok", " ... ignored"),
        ):
            with self.subTest(replacement=replacement):
                self.assert_refused(self.observed.replace(self.EXACT_CASE, replacement, 1))

    def test_zero_or_multiple_case_results_are_refused(self):
        for changed in (
            self.observed.replace(self.EXACT_CASE + "\n", "", 1),
            self.observed.replace(self.EXACT_CASE + "\n", (self.EXACT_CASE + "\n") * 2, 1),
        ):
            with self.subTest(text=changed):
                self.assert_refused(changed)

    def test_wrong_or_multiple_diagnostics_are_refused(self):
        for changed in (
            self.observed.replace("error[E0308]:", "error[E0309]:"),
            self.observed.replace("error[E0308]:", "error:"),
            self.observed + "error[E0000]: additional diagnostic\n",
        ):
            with self.subTest(text=changed):
                self.assert_refused(changed)

    def test_wrong_type_boundary_context_is_refused(self):
        for old, new in (
            ("CellPqReleaseExpectationV2", "DifferentExpectation"),
            ("integer", "different value"),
            ("release_at(300)", "release_at(301)"),
        ):
            with self.subTest(missing=old):
                self.assert_refused(self.observed.replace(old, new))

    def test_summary_count_status_and_uniqueness_are_required(self):
        for changed in (
            self.observed.replace(self.SUMMARY, ""),
            self.observed + self.SUMMARY + "\n",
            self.observed.replace("test result: ok.", "test result: FAILED."),
            self.observed.replace("1 passed;", "0 passed;"),
            self.observed.replace("1 passed;", "2 passed;"),
            self.observed.replace("0 failed;", "1 failed;"),
            self.observed.replace("0 ignored;", "1 ignored;"),
            self.observed.replace("0 measured;", "1 measured;"),
        ):
            with self.subTest(text=changed):
                self.assert_refused(changed)

    def test_fixture_keeps_original_source_and_failed_job_provenance(self):
        self.assertEqual(self.observation["source_commit"],
                         "66b7064be597039ce871b5b12ad5568850a2dd46")
        self.assertEqual(self.observation["source_tree"],
                         "75ac72605e3647de5a09557bfd7012dc99b0dec6")
        self.assertEqual(self.observation["original_doctest_exit_code"], 0)
        self.assertEqual(self.observation["original_readback_exit_code"], 1)
        self.assertEqual(self.observation["original_job_conclusion"], "failure")
        self.assertEqual(self.observation["log_sha256"], self.ORIGINAL_SHA256)
        self.assertEqual(self.observation["log_bytes"], 1159)
        self.assertEqual(self.observation["source_file_sha256"],
                         "7326da0ad2c31fe599300d928fde84129ce83de0b072ef3bb46799d424aca3eb")
        self.assertIn("(line 364)", self.EXACT_CASE)
        self.assertEqual(self.observed.count(self.EXACT_CASE), 1)

    def test_current_source_location_is_derived_and_wrong_locations_stay_refused(self):
        source = (self.root / self.reader.SOURCE).read_text()
        line = self.reader.source_line(source)
        shifted = self.observed.replace("(line 364)", "(line " + str(line) + ")")
        self.assertEqual(self.reader.inspect(shifted, line)["result"], "PASS")
        self.assertEqual(self.reader.inspect(shifted, line + 1)["result"], "FAIL")
        self.assertEqual(self.reader.source_line("// Unrelated insertion.\n" + source), line + 1)

    def test_missing_or_ambiguous_source_example_is_refused(self):
        source = (self.root / self.reader.SOURCE).read_text()
        for changed in (source.replace("```compile_fail,E0308", "```compile_fail,E0309"),
                        source.replace("let _ = proof.release_at(300);", "let _ = proof.release_at(301);"),
                        source.replace("pub struct VerifiedCellPqReleaseV2", "pub struct DifferentProof"),
                        source + source):
            with self.subTest(changed=changed[-80:]):
                with self.assertRaises(ValueError):
                    self.reader.source_line(changed)



class PqSystemSupplementalControlTests(unittest.TestCase):
    """Exercise selection and failure propagation with explicit shell test doubles."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in (PQ_RELEASE_WORKFLOW, PQ_SYSTEM_REQUIRED_MANIFEST,
                         PQ_SYSTEM_SUPPLEMENTAL_MANIFEST,
                         'scripts/ci/check_required_native_test.py'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.workflow = (self.root / PQ_RELEASE_WORKFLOW).read_text()
        self.retained = json.loads((self.root / PQ_SYSTEM_REQUIRED_MANIFEST).read_text())
        self.supplement = json.loads((self.root / PQ_SYSTEM_SUPPLEMENTAL_MANIFEST).read_text())

    def write_manifest(self, relative, value):
        (self.root / relative).write_text(json.dumps(value, indent=2) + '\n')

    # Independent expectations for the actual hosted step, including its
    # unchanged two migration controls. These shell doubles never execute Rust.
    CHECKPOINT_CASES = (
        'rejected_nonprivate_socket_parent_does_not_unlink_existing_listener',
        'different_admitted_journal_cannot_replace_a_live_checkpoint_endpoint',
        'copied_lease_record_cannot_replace_a_live_checkpoint_endpoint',
        'connect_only_probe_preserves_live_owner_and_journal',
        'complete_checkpoint_request_rejects_a_copied_lease_replacement',
    )
    PROBE_CASES = (
        'socket_owner_v1::tests::saturated_copied_lease_refuses_without_unlink_and_allows_dead_recovery',
        'socket_owner_v1::tests::endpoint_lease_prevents_live_socket_replacement_and_permits_owner_restart',
        'socket_owner_v1::probe_policy_tests::connected_listener_is_not_stale',
        'socket_owner_v1::probe_policy_tests::explicit_refusal_is_only_recovery_case',
        'socket_owner_v1::probe_policy_tests::every_other_error_stays_refused',
        'socket_owner_v1::probe_policy_tests::linux_eagain_and_einprogress_are_not_dead_listener',
        'socket_owner_v1::unsupported_probe_tests::other_unix_policy_never_probes_or_authorizes_replacement',
    )
    HANDOFF_CASES = (
        'store::pq_migration_inventory::handoff_tests::admitted_restricted_source_handoff_preserves_nonce_liability_and_claim_on_cold_open',
        'store::pq_migration_inventory::handoff_tests::admitted_source_handoff_refuses_wrong_registry_pins_and_unsupported_source_rows',
    )

    def test_checkpoint_step_cannot_drop_original_or_new_controls_or_ignore_failure(self):
        step = PQ_CHECKPOINT_OWNERSHIP_STEP
        changes = [
            ('missing-step', ''),
            ('duplicate-step', step + step),
            ('disabled', step.replace(
                "!cancelled() && steps.pq_build.outcome == 'success'", 'false')),
            ('substring', step.replace(' -- --exact ', ' -- ')),
            ('readback', step.replace('python3 scripts/ci/check_required_native_test.py', 'true')),
            ('swallow', step.replace('failed=1', 'failed=0')),
        ]
        changes.extend((name, step.replace(name, 'renamed_' + name, 1))
                       for name in (*self.CHECKPOINT_CASES, *self.PROBE_CASES))
        for label, changed_step in changes:
            with self.subTest(label=label):
                changed = self.workflow.replace(step, changed_step, 1)
                self.assertNotEqual(changed, self.workflow)
                (self.root / PQ_RELEASE_WORKFLOW).write_text(changed)
                with self.assertRaisesRegex(ValueError, 'PQ checkpoint'):
                    check_pq_system_required_controls(self.root)

    def run_checkpoint_shell(self, mode='pass', failure_selector=None):
        out = Path(tempfile.mkdtemp(prefix='synthetic-checkpoint-' + mode + '-',
                                    dir=self.root))
        (out / 'selection.json').write_text(json.dumps({
            'migration': self.HANDOFF_CASES,
            'checkpoint': self.CHECKPOINT_CASES,
            'probe': self.PROBE_CASES,
        }))
        (out / 'run-command.sh').write_text(
            'set -euo pipefail\npython3 "$PQ_OUT/synthetic-command.py" "$@"\n')
        (out / 'synthetic-command.py').write_text(r'''
import json, os, sys
from pathlib import Path
out = Path(os.environ['PQ_OUT'])
groups = json.loads((out / 'selection.json').read_text())
names = [*groups['migration'], *groups['checkpoint'], *groups['probe']]
label, *command = sys.argv[1:]
selector = command[command.index('--') - 1]
if selector in groups['migration']:
    target = ['trnm-pon-node', '--lib', '--all-features']
    expected_label = 'migration-' + selector.rsplit('::', 1)[-1]
elif selector in groups['probe']:
    target = ['trnm-checkpoint-store', '--lib']
    expected_label = 'checkpoint-probe-' + selector.rsplit('::', 1)[-1]
else:
    target = ['trnm-checkpoint-store', '--test', 'socket_ownership']
    expected_label = 'checkpoint-' + selector
expected = ['cargo', '+1.95.0', 'test', '--locked', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', *target, selector,
            '--', '--exact', '--show-output', '--test-threads=1']
assert command == expected and selector in names
assert label == expected_label
with (out / 'calls.jsonl').open('a') as calls:
    calls.write(json.dumps({'label': label, 'selector': selector}) + '\n')
mode = os.environ['TRNM_PQ_SYNTHETIC_MODE'] if selector == os.environ['TRNM_PQ_FAILURE_SELECTOR'] else 'pass'
if mode == 'failed-command':
    raise SystemExit(1)
name = 'wrong_control' if mode == 'wrong-name' else selector
raw = f'running 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
if mode == 'zero':
    raw = 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
(out / (label + '.log')).write_text(raw)
''')
        body = textwrap.dedent(PQ_CHECKPOINT_OWNERSHIP_STEP.split('        run: |\n', 1)[1])
        result = subprocess.run(
            ['bash', '-c', body], cwd=self.root, capture_output=True, text=True,
            env={**os.environ, 'PQ_OUT': str(out), 'TRNM_PQ_SYNTHETIC_MODE': mode,
                 'TRNM_PQ_FAILURE_SELECTOR': failure_selector or self.CHECKPOINT_CASES[-1]})
        calls = [json.loads(line) for line in (out / 'calls.jsonl').read_text().splitlines()]
        return result, calls, out

    def test_checkpoint_shell_selects_ownership_and_bounded_probe_controls_once(self):
        result, calls, out = self.run_checkpoint_shell()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([row['selector'] for row in calls],
                         [*self.HANDOFF_CASES, *self.CHECKPOINT_CASES, *self.PROBE_CASES])
        for row in calls:
            readback = json.loads((out / (row['label'] + '-execution.json')).read_text())
            self.assertEqual(readback['test'], row['selector'])
            self.assertEqual(readback['executed_tests'], 1)
            self.assertEqual(readback['scope'], 'named-libtest-execution-only')

    def test_checkpoint_fencing_and_probe_command_or_readback_failure_is_fatal(self):
        for selector in (self.CHECKPOINT_CASES[-1], self.PROBE_CASES[-1]):
            for mode in ('zero', 'wrong-name', 'failed-command'):
                with self.subTest(selector=selector, mode=mode):
                    result, calls, _ = self.run_checkpoint_shell(mode, selector)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual([row['selector'] for row in calls],
                                     [*self.HANDOFF_CASES, *self.CHECKPOINT_CASES, *self.PROBE_CASES])

    def test_retains_52_and_separately_requires_eleven_without_claiming_execution(self):
        self.assertEqual(check_pq_system_required_controls(self.root), {
            'retained_meaningful_controls': 52, 'supplemental_meaningful_controls': 11,
            'selected_meaningful_controls': 63, 'tests_executed': False})

    def test_original_roster_name_count_order_and_scope_cannot_change(self):
        mutations = (
            ('remove', lambda value: value['tests'].pop()),
            ('rename', lambda value: value['tests'].__setitem__(0, 'a::renamed')),
            ('duplicate', lambda value: value['tests'].__setitem__(0, value['tests'][1])),
            ('reorder', lambda value: value['tests'].reverse()),
            ('counter', lambda value: value.__setitem__('expected_meaningful_controls', 59)),
            ('qualification', lambda value: value.__setitem__('whole_chain_quantum_security_qualified', True)),
            ('child', lambda value: value.__setitem__('child_process_harnesses_not_counted', [])),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = json.loads(json.dumps(self.retained))
                mutate(value)
                self.write_manifest(PQ_SYSTEM_REQUIRED_MANIFEST, value)
                with self.assertRaisesRegex(ValueError, 'PQ system'):
                    check_pq_system_required_controls(self.root)

    def test_supplement_requires_exact_full_names_and_separate_unchanged_budgets(self):
        mutations = (
            ('missing', lambda value: value['tests'].pop()),
            ('empty', lambda value: value['tests'].__setitem__(0, '')),
            ('short', lambda value: value['tests'].__setitem__(0, value['tests'][0].rsplit('::', 1)[1])),
            ('duplicate', lambda value: value['tests'].__setitem__(0, value['tests'][1])),
            ('retained', lambda value: value['tests'].__setitem__(0, self.retained['tests'][0])),
            ('child', lambda value: value['tests'].__setitem__(0, self.retained['child_process_harnesses_not_counted'][0])),
            ('counter', lambda value: value.__setitem__('expected_meaningful_controls', 6)),
            ('bool-counter', lambda value: value.__setitem__('expected_meaningful_controls', True)),
            ('retained-counter', lambda value: value.__setitem__('retained_meaningful_controls', 59)),
            ('budget', lambda value: value.__setitem__('original_business_budgets_changed', True)),
            ('qualification', lambda value: value.__setitem__('whole_chain_quantum_security_qualified', True)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = json.loads(json.dumps(self.supplement))
                mutate(value)
                self.write_manifest(PQ_SYSTEM_SUPPLEMENTAL_MANIFEST, value)
                with self.assertRaisesRegex(ValueError, 'PQ system supplement'):
                    check_pq_system_required_controls(self.root)

    def test_prior_seven_only_cannot_satisfy_extended_pq_account_roster(self):
        # Preserve the old observation scope: neither its seven-name list nor
        # a matching old counter proves execution of the four added controls.
        prior = json.loads(json.dumps(self.supplement))
        prior['tests'] = prior['tests'][:7]
        for count in (7, 11):
            with self.subTest(declared_count=count):
                prior['expected_meaningful_controls'] = count
                self.write_manifest(PQ_SYSTEM_SUPPLEMENTAL_MANIFEST, prior)
                with self.assertRaisesRegex(ValueError, 'PQ system supplement'):
                    check_pq_system_required_controls(self.root)

    def test_hosted_supplement_cannot_skip_duplicate_filter_or_ignore_readback(self):
        step = PQ_SYSTEM_SUPPLEMENTAL_STEP
        mutations = (
            ('remove', self.workflow.replace(step, '', 1)),
            ('duplicate', self.workflow.replace(step, step + step, 1)),
            ('disabled', self.workflow.replace(step, step.replace(
                "if: ${{ !cancelled() && steps.pq_build.outcome == 'success' }}", 'if: false'), 1)),
            ('substring', self.workflow.replace(step, step.replace(' -- --exact ', ' -- '), 1)),
            ('readback', self.workflow.replace(step, step.replace(
                'python3 scripts/ci/check_required_native_test.py', 'true'), 1)),
            ('swallow', self.workflow.replace(step, step.replace('failed=1', 'failed=0'), 1)),
            ('trigger', self.workflow.replace(
                '      - ' + PQ_SYSTEM_SUPPLEMENTAL_MANIFEST + '\n', '', 1)),
            ('retained-step', self.workflow.replace(PQ_SYSTEM_REQUIRED_STEP, '', 1)),
            ('budget', self.workflow.replace(
                '    timeout-minutes: 90\n', '    timeout-minutes: 120\n', 1)),
        )
        for label, text in mutations:
            with self.subTest(label=label):
                self.assertNotEqual(text, self.workflow)
                (self.root / PQ_RELEASE_WORKFLOW).write_text(text)
                with self.assertRaisesRegex(ValueError, 'PQ'):
                    check_pq_system_required_controls(self.root)

    def run_supplemental_shell(self, mode='pass'):
        # Execute the actual workflow body and real transcript reader. The
        # command recorder below is deliberately a test double, never Rust
        # execution evidence.
        out = self.root / ('synthetic-' + mode)
        out.mkdir()
        (out / 'run-command.sh').write_text(
            'set -euo pipefail\npython3 "$PQ_OUT/synthetic-command.py" "$@"\n')
        (out / 'synthetic-command.py').write_text(r'''
import json, os, sys
from pathlib import Path
out = Path(os.environ['PQ_OUT'])
names = json.loads(Path('config/pon/pq-system-supplemental-tests-v1.json').read_text())['tests']
label, *command = sys.argv[1:]
selector = command[10]
expected = ['cargo', '+1.95.0', 'test', '--locked', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib',
            '--all-features', selector, '--', '--exact', '--show-output', '--test-threads=1']
assert command == expected and selector in names
assert label == f'native-supplemental-{names.index(selector):02d}'
with (out / 'calls.jsonl').open('a') as calls:
    calls.write(json.dumps({'label': label, 'selector': selector, 'command': command}) + '\n')
mode = os.environ['TRNM_PQ_SYNTHETIC_MODE'] if selector == names[0] else 'pass'
if mode == 'failed-command':
    raise SystemExit(1)
name = 'wrong::control' if mode == 'wrong-name' else selector
raw = f'running 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
if mode == 'zero':
    raw = 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
elif mode == 'duplicate':
    raw += raw
elif mode == 'ignored':
    raw = raw.replace('1 passed; 0 failed; 0 ignored', '0 passed; 0 failed; 1 ignored')
(out / (label + '.log')).write_text(raw)
''')
        body = textwrap.dedent(PQ_SYSTEM_SUPPLEMENTAL_STEP.split('        run: |\n', 1)[1])
        result = subprocess.run(
            ['bash', '-c', body], cwd=self.root, capture_output=True, text=True,
            env={**os.environ, 'PQ_OUT': str(out), 'TRNM_PQ_SYNTHETIC_MODE': mode})
        calls_path = out / 'calls.jsonl'
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
        return result, calls, out

    def test_workflow_body_selects_each_full_name_once_and_reads_back_every_run(self):
        result, calls, out = self.run_supplemental_shell()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([row['selector'] for row in calls], self.supplement['tests'])
        self.assertEqual(len({row['label'] for row in calls}), 11)
        for row in calls:
            readback = json.loads((out / (row['label'] + '-execution.json')).read_text())
            self.assertEqual(readback['test'], row['selector'])
            self.assertEqual(readback['executed_tests'], 1)
            self.assertEqual(readback['scope'], 'named-libtest-execution-only')

    def test_real_reader_failures_and_command_failure_fail_after_attempting_all_controls(self):
        for mode in ('zero', 'duplicate', 'wrong-name', 'ignored', 'failed-command'):
            with self.subTest(mode=mode):
                result, calls, _ = self.run_supplemental_shell(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([row['selector'] for row in calls], self.supplement['tests'])

    def test_invalid_selector_lists_stop_before_any_native_command(self):
        for label, names in (
                ('empty', [''] + self.supplement['tests'][1:]),
                ('duplicate', [self.supplement['tests'][1]] + self.supplement['tests'][1:]),
                ('missing', self.supplement['tests'][:-1]),
                ('retained', [self.retained['tests'][0]] + self.supplement['tests'][1:])):
            with self.subTest(label=label):
                value = json.loads(json.dumps(self.supplement))
                value['tests'] = names
                self.write_manifest(PQ_SYSTEM_SUPPLEMENTAL_MANIFEST, value)
                result, calls, _ = self.run_supplemental_shell(label)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
