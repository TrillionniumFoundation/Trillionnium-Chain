#!/usr/bin/env python3
"""Exercise the actual CI Python gates with isolated roster/report mutations.

Discovery fixtures use inert cases carrying real required IDs, so exercising the
named runner does not execute the scientific suites or recursively run this file.
The outer CI lane runs the real suites. No YAML package, prover, Rust or network
is used here; the gates are extracted directly from their step/heredoc boundaries.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import textwrap
import traceback
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-w1-qrom-implementation.yml'
ROSTER = 'config/pon/w1-qrom-required-tests-v2.json'
REQUIRED_STAGES = (
    'observations', 'checkout', 'source_before', 'preflight', 'named_tests',
    'implementation', 'budget_unknown', 'budget_hypothetical',
    'report_scopes', 'source_after',
)
HEAD = 'a' * 40
BASE = 'b' * 40

sys.path.insert(0, str(ROOT / 'scripts'))
import w1_qrom_conditional_budget as budget
import w1_qrom_implementation_audit_v2 as implementation


def embedded_python(workflow: str, step_id: str) -> str:
    """Extract one reviewed layout; fail rather than silently select another step."""
    lines = workflow.splitlines()
    markers = [i for i, line in enumerate(lines)
               if line == '        id: ' + step_id]
    if len(markers) != 1:
        raise ValueError('expected one workflow step: ' + step_id)
    start = markers[0]
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith('      - name:')), len(lines))
    block = lines[start:end]
    openers = [i for i, line in enumerate(block)
               if re.search(r"\bpython3\b.*<<'PY'", line)]
    if len(openers) != 1:
        raise ValueError('expected one Python heredoc: ' + step_id)
    first = openers[0] + 1
    closers = [i for i in range(first, len(block)) if block[i].strip() == 'PY']
    if len(closers) != 1:
        raise ValueError('expected one heredoc terminator: ' + step_id)
    return textwrap.dedent('\n'.join(block[first:closers[0]])) + '\n'


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True, allow_nan=False) + '\n')


def read_json(path: Path):
    return json.loads(path.read_text())


def named_fixture(test_id: str, skipped: bool = False):
    # Define this class locally: unittest discovery must not collect the fixture
    # itself as an extra permanent test in this module.
    class IsolatedNamedCase(unittest.TestCase):
        def id(self):
            return test_id

        def runTest(self):
            if skipped:
                self.skipTest('isolated workflow-gate negative control')

    return IsolatedNamedCase()


class WorkflowGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow_text = WORKFLOW.read_text()
        cls.codes = {step: embedded_python(cls.workflow_text, step)
                     for step in ('named_tests', 'report_scopes', 'status')}
        cls.roster_bytes = (ROOT / ROSTER).read_bytes()
        cls.roster = json.loads(cls.roster_bytes)
        # Actual project reports are the positive baseline. Tests mutate their
        # concrete values; they do not reproduce the gate's arithmetic rules.
        cls.reports = {
            'implementation.json': implementation.build_report(ROOT),
            'budget-unknown.json': budget.make_report(
                {'schema': budget.INPUT_SCHEMA, 'input_kind': 'hypothetical'}),
            'budget-hypothetical.json': budget.make_report(budget.example_input()),
            'budget-hypothetical-input.json': budget.serializable(budget.example_input()),
        }

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='w1-workflow-gate-')
        self.addCleanup(self.temporary.cleanup)
        self.temp = Path(self.temporary.name)
        self.case_number = 0

    def workspace(self, reports=None):
        self.case_number += 1
        root = self.temp / str(self.case_number)
        out = root / 'observations'
        out.mkdir(parents=True)
        roster_path = root / ROSTER
        roster_path.parent.mkdir(parents=True)
        roster_path.write_bytes(self.roster_bytes)
        for name, report in (self.reports if reports is None else reports).items():
            write_json(out / name, report)
        identity = {
            'schema': 'trnm-ci-source-v1', 'kind': 'head',
            'tested_commit': HEAD, 'tested_tree': 'c' * 40, 'candidate': HEAD,
            'base': None, 'prospective_merge': None, 'tracked_worktree_verified': True,
            'tracked_entries': 1, 'tracked_bytes': 1,
            'tests_executed_by_identity_check': False,
        }
        for name in ('source-before.json', 'source-after.json'):
            write_json(out / name, identity)
        return root, out

    def execute(self, step, root, out, *, steps=None):
        if steps is None:
            steps = {name: {'outcome': 'success', 'conclusion': 'success'}
                     for name in REQUIRED_STAGES}
        environment = {
            'W1_QROM_STEP_RESULTS': json.dumps(steps), 'SOURCE_KIND': 'head',
            'EXPECTED_SOURCE': HEAD, 'EXPECTED_HEAD': HEAD, 'EXPECTED_BASE': BASE,
        }
        stdout, stderr = io.StringIO(), io.StringIO()
        exit_code = 0
        with working_directory(root), mock.patch.object(sys, 'argv', ['gate', str(out)]), \
                mock.patch.dict(os.environ, environment), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                exec(compile(self.codes[step], str(WORKFLOW) + ':' + step, 'exec'),
                     {'__name__': '__main__'})
            except SystemExit as error:
                exit_code = error.code if type(error.code) is int else int(error.code is not None)
                if error.code is not None and not isinstance(error.code, int):
                    print(str(error.code), file=sys.stderr)
            except Exception:
                exit_code = 1  # An uncaught exception also fails a real Python step.
                traceback.print_exc()
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def run_named(self, root, out, mode='success'):
        suites = {row['module']: row['tests'] for row in self.roster['suites']}
        first = self.roster['suites'][0]['module']
        directory = root / 'scripts/ci'
        directory.mkdir(parents=True, exist_ok=True)
        if mode == 'import_exit_zero':
            (directory / (first + '.py')).write_text('raise SystemExit(0)\n')
        elif mode == 'load_tests_exit_zero':
            (directory / (first + '.py')).write_text(
                'def load_tests(loader, standard_tests, pattern):\n    raise SystemExit(0)\n')
        discover = unittest.TestLoader.discover

        def isolated_discovery(loader, start_dir, pattern='test*.py', top_level_dir=None):
            module = Path(pattern).stem
            if module == first and mode in ('import_exit_zero', 'load_tests_exit_zero'):
                return discover(loader, start_dir, pattern, top_level_dir)
            names = list(suites[module])
            if module == first and mode == 'missing':
                names.pop()
            if module == first and mode == 'duplicate':
                names.append(names[0])
            return unittest.TestSuite(named_fixture(name, module == first and mode == 'skip' and i == 0)
                                      for i, name in enumerate(names))

        # Earlier real suites may already have imported the same name. Save and
        # restore it so the negative import really targets the isolated module.
        cached = sys.modules.pop(first, None)
        try:
            with mock.patch.object(sys, 'path', [str(directory)] + list(sys.path)), \
                    mock.patch.object(unittest.TestLoader, 'discover', isolated_discovery):
                return self.execute('named_tests', root, out)
        finally:
            sys.modules.pop(first, None)
            if cached is not None:
                sys.modules[first] = cached

    def completed_workspace(self):
        root, out = self.workspace()
        result = self.run_named(root, out)
        self.assertEqual(result[0], 0, result[2])
        self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], True)
        return root, out

    def assert_scope_rejected(self, mutate):
        reports = deepcopy(self.reports)
        mutate(reports)
        root, out = self.workspace(reports)
        result = self.execute('report_scopes', root, out)
        self.assertNotEqual(result[0], 0, 'actual workflow accepted the mutated report')

    def test_named_roster_executes_exactly_once_without_recursing_into_real_suites(self):
        root, out = self.completed_workspace()
        report = read_json(out / 'named-tests.json')
        self.assertEqual(report['required_tests'], self.roster['expected_tests'])
        self.assertEqual([row['module'] for row in report['suites']],
                         [row['module'] for row in self.roster['suites']])
        self.assertTrue(all(row['tests_run'] == len(row['success_ids']) for row in report['suites']))

    def test_named_import_system_exit_zero_is_rejected(self):
        root, out = self.workspace()
        result = self.run_named(root, out, 'import_exit_zero')
        self.assertNotEqual(result[0], 0, 'SystemExit(0) must not be a successful test stage')
        self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], False)

    def test_named_load_tests_system_exit_zero_is_rejected(self):
        root, out = self.workspace()
        result = self.run_named(root, out, 'load_tests_exit_zero')
        self.assertNotEqual(result[0], 0, 'load_tests SystemExit(0) must not complete the roster')
        self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], False)

    def test_named_missing_duplicate_and_skipped_controls_are_rejected(self):
        for mode in ('missing', 'duplicate', 'skip'):
            with self.subTest(mode=mode):
                root, out = self.workspace()
                result = self.run_named(root, out, mode)
                self.assertNotEqual(result[0], 0)
                self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], False)

    def test_status_rejects_exit_zero_without_named_completion(self):
        root, out = self.completed_workspace()
        (out / 'named-tests.json').unlink()  # All other evidence and step successes remain.
        result = self.execute('status', root, out)
        self.assertNotEqual(result[0], 0, 'successful steps cannot replace a completion record')
        self.assertIs(read_json(out / 'ci-status.json')['all_required_observations_passed'], False)

    def test_status_independently_rechecks_named_ids_and_boolean_scope(self):
        for mutation in ('missing_success', 'duplicate_success', 'skip', 'scope_zero', 'passed_one'):
            with self.subTest(mutation=mutation):
                root, out = self.completed_workspace()
                report = read_json(out / 'named-tests.json')
                first = report['suites'][0]
                if mutation == 'missing_success':
                    first['success_ids'].pop()
                elif mutation == 'duplicate_success':
                    first['success_ids'].append(first['success_ids'][0])
                elif mutation == 'skip':
                    first['skipped'] = [[first['expected_ids'][0], 'retained skipped control']]
                elif mutation == 'scope_zero':
                    report['post_quantum_soundness_qualified'] = 0
                else:
                    report['all_named_controls_passed'] = 1
                write_json(out / 'named-tests.json', report)
                result = self.execute('status', root, out)
                self.assertNotEqual(result[0], 0)
                self.assertIs(read_json(out / 'ci-status.json')['all_required_observations_passed'], False)

    def test_status_requires_every_step_outcome_and_conclusion(self):
        root, out = self.completed_workspace()
        positive = self.execute('status', root, out)
        self.assertEqual(positive[0], 0, positive[2])
        self.assertIs(read_json(out / 'ci-status.json')['all_required_observations_passed'], True)
        for stage in REQUIRED_STAGES:
            for field, value in (('outcome', 'failure'), ('conclusion', 'skipped')):
                with self.subTest(stage=stage, field=field):
                    root, out = self.completed_workspace()
                    steps = {name: {'outcome': 'success', 'conclusion': 'success'}
                             for name in REQUIRED_STAGES}
                    steps[stage][field] = value
                    result = self.execute('status', root, out, steps=steps)
                    self.assertNotEqual(result[0], 0)
                    status = read_json(out / 'ci-status.json')
                    self.assertIn(stage, status['failed_or_skipped_stages'])
                    self.assertIs(status['all_required_observations_passed'], False)

    def test_actual_unknown_and_hypothetical_reports_pass_the_scope_gate(self):
        root, out = self.workspace()
        result = self.execute('report_scopes', root, out)
        self.assertEqual(result[0], 0, result[2])

    def test_unknown_report_requires_all_input_and_component_names(self):
        def missing_input(reports):
            del reports['budget-unknown.json']['inputs']['pqsr']['t']

        def substituted_inputs(reports):
            reports['budget-unknown.json']['inputs']['pqsr'] = {'missing_every_required_input': None}

        def empty_components(reports):
            reports['budget-unknown.json']['merkle_components']['conditional_expressions'] = {}

        for mutation in (missing_input, substituted_inputs, empty_components):
            with self.subTest(mutation=mutation.__name__):
                self.assert_scope_rejected(mutation)

    def test_unknown_report_cannot_infer_derived_values_or_comparisons(self):
        cases = (
            ('rrbr_coefficient', {'numerator': '1', 'denominator': '1'}),
            ('finite_randomness_addend', {'numerator': '1', 'denominator': '2'}),
            ('rrbr_addend', {'numerator': '1', 'denominator': '2'}),
            ('conditional_expression_meets_target', True),
        )
        for key, value in cases:
            with self.subTest(field=key):
                def change(reports, key=key, value=value):
                    reports['budget-unknown.json']['pqsr_component'][key] = value
                self.assert_scope_rejected(change)

        def inferred_allowance(reports):
            reports['budget-unknown.json']['pqsr_component']['target_analysis'][
                'kappa_rrbr_required_at_most'] = {'numerator': '1', 'denominator': '1'}
        self.assert_scope_rejected(inferred_allowance)

    def test_hypothetical_report_requires_nonnull_component_results(self):
        def null_upper(reports):
            reports['budget-hypothetical.json']['pqsr_component']['conditional_upper_expression'] = None

        def empty_components(reports):
            reports['budget-hypothetical.json']['merkle_components']['conditional_expressions'] = {}

        def null_component(reports):
            reports['budget-hypothetical.json']['merkle_components']['conditional_expressions'][
                'offline_extractability'] = None

        for mutation in (null_upper, empty_components, null_component):
            with self.subTest(mutation=mutation.__name__):
                self.assert_scope_rejected(mutation)

    def test_hypothetical_report_rejects_wrong_fractions_and_numeric_booleans(self):
        paths = (
            ('pqsr_component', 'conditional_upper_expression'),
            ('pqsr_component', 'rrbr_coefficient'),
            ('merkle_components', 'conditional_expressions', 'offline_extractability'),
        )
        for path in paths:
            with self.subTest(path=path):
                def change(reports, path=path):
                    current = reports['budget-hypothetical.json']
                    for key in path:
                        current = current[key]
                    current['numerator'] = str(int(current['numerator']) + 1)
                self.assert_scope_rejected(change)

        def numeric_true(reports):
            reports['budget-hypothetical.json']['pqsr_component']['conditional_expression_meets_target'] = 1
        self.assert_scope_rejected(numeric_true)

    def test_hypothetical_report_rejects_inexact_fraction_input(self):
        for value in (1.9, True, '01'):
            with self.subTest(numerator=value):
                def change(reports, value=value):
                    reports['budget-hypothetical.json']['inputs']['pqsr']['kappa_rrbr']['numerator'] = value
                self.assert_scope_rejected(change)

    def test_report_scope_rejects_qualification_escalation_and_false_as_zero(self):
        def true_implementation(reports):
            reports['implementation.json']['qualification']['complete_w1_soundness_qualified'] = True

        def zero_qualification(reports):
            reports['implementation.json']['qualification']['post_quantum_soundness_qualified'] = 0

        def inferred_bits(reports):
            reports['budget-unknown.json']['qualification']['quantum_security_bits'] = 128

        def full_theorem(reports):
            reports['budget-hypothetical.json']['theorem_11_3_full_bound'] = 0

        def latest_revision(reports):
            reports['budget-hypothetical.json']['source']['latest_revision_full_text_equivalence_verified'] = True

        for mutation in (true_implementation, zero_qualification, inferred_bits, full_theorem, latest_revision):
            with self.subTest(mutation=mutation.__name__):
                self.assert_scope_rejected(mutation)

        for key in ('new_native_once_route_qualified', 'funded_service_decoder_qualified',
                    'whole_source_and_build_equivalence_proved'):
            for value in (True, 0, None, 'false'):
                with self.subTest(source_review=key, value=value):
                    def change(reports, key=key, value=value):
                        reports['implementation.json']['source_review'][key] = value
                    self.assert_scope_rejected(change)
            with self.subTest(missing_source_review=key):
                def missing(reports, key=key):
                    del reports['implementation.json']['source_review'][key]
                self.assert_scope_rejected(missing)

        changes = {
            'historical_engine_sha256': '0' * 64,
            'historical_contract_sha256': '0' * 64,
            'historical_report_sha256': '0' * 64,
            'selected_project_file_count': 16.0,
            'unchanged_project_file_count': True,
            'historical_route_byte_projection_reproduced': 1,
            'historical_semantic_report_fields_reproduced': False,
            'changed_paths': [],
            'schema': 'TRNM-W1-QROM-SOURCE-TRANSITION0',
            'unreviewed_source_qualified': False,
        }
        for key, value in changes.items():
            with self.subTest(source_transition=key):
                def change(reports, key=key, value=value):
                    reports['implementation.json']['source_review'][key] = value
                self.assert_scope_rejected(change)


if __name__ == '__main__':
    unittest.main()
