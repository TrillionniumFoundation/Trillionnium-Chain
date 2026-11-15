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
ROSTER = 'config/pon/w1-qrom-required-tests-v1.json'
# Independent current-job stage contract; the historical name runner stays separate.
REQUIRED_STAGES = (
    'observations', 'checkout', 'source_before', 'preflight', 'named_tests',
    'historical_drift', 'implementation',
    'supplemental_historical_controls', 'supplemental_historical_mapping',
    'supplemental_current_mapping', 'supplemental_budget_unknown',
    'supplemental_budget_hypothetical', 'supplemental_report_scopes', 'source_after',
)
HEAD = 'a' * 40
BASE = 'b' * 40

sys.path.insert(0, str(ROOT / 'scripts'))
import w1_qrom_conditional_budget as budget
import w1_qrom_implementation_audit as implementation
import w1_qrom_historical_fixture as historical
import w1_qrom_current_implementation_audit as current
import w1_qrom_supplemental_controls as supplemental
import w1_qrom_current_ci as current_ci


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
        # The two source jobs deliberately reuse step IDs. Bind the original
        # historical job before selecting its exact embedded gate boundaries.
        current_ci.validate_historical_job(cls.workflow_text)
        historical_job, current_job = cls.workflow_text.split(
            '  qrom-historical-implementation:\n', 1)[1].split(
            '  qrom-current-implementation:\n', 1)
        # Original named-runner controls belong to the fixed historical job.
        # Relocated mapping/budget controls belong to the current supplemental step.
        cls.codes = {
            'named_tests': embedded_python(historical_job, 'named_tests'),
            'report_scopes': embedded_python(current_job, 'supplemental_report_scopes'),
        }
        if REQUIRED_STAGES != current_ci.REQUIRED_STAGES or any(
                current_job.count('        id: ' + stage + '\n') != 1
                for stage in REQUIRED_STAGES):
            raise ValueError('independent current stage roster differs from the actual workflow')
        verify_command = (
            '          python3 scripts/ci/w1_qrom_current_ci.py verify '
            '--repo-root "$GITHUB_WORKSPACE" --out "$w1_qrom_current_out" '
            '--kind "$SOURCE_KIND" --expected-source "$EXPECTED_SOURCE" '
            '--expected-head "$EXPECTED_HEAD" --expected-base "$EXPECTED_BASE" '
            '2>&1 | tee "$w1_qrom_current_out/current-ci-status.log"\n')
        if current_job.count(verify_command) != 1 or current_job.count(
                '          W1_QROM_CURRENT_STEP_RESULTS: $' + '{{ toJSON(steps) }}\n') != 1:
            raise ValueError('current final gate invocation differs')
        cls.current_roster, cls.current_roster_bytes = current_ci.load_roster(ROOT)
        with tempfile.TemporaryDirectory(prefix='current-workflow-drift-') as directory:
            cls.current_drift = current_ci.observe_drift(ROOT, Path(directory))
            cls.drift_stdout = (Path(directory) / 'historical-on-current.stdout.log').read_bytes()
            cls.drift_stderr = (Path(directory) / 'historical-on-current.stderr.log').read_bytes()
        cls.roster_bytes = (ROOT / ROSTER).read_bytes()
        cls.roster = json.loads(cls.roster_bytes)
        cls.supplemental_roster, cls.supplemental_roster_bytes = supplemental.load_roster(ROOT)
        # Actual project reports are the positive baseline. Tests mutate their
        # concrete values; they do not reproduce the gate's arithmetic rules.
        historical_report, historical_receipt = historical.historical_mapping(ROOT)
        cls.reports = {
            'implementation.json': historical_report,
            'historical-source.json': historical_receipt,
            'current-v1-refusal.json': historical.current_v1_refusal(ROOT),
            'implementation-current.json': current.build_report(ROOT),
            'budget-unknown.json': budget.make_report(
                {'schema': budget.INPUT_SCHEMA, 'input_kind': 'hypothetical'}),
            'budget-hypothetical.json': budget.make_report(budget.example_input()),
            'budget-hypothetical-input.json': budget.serializable(budget.example_input()),
        }
        # Inert named cases isolate the completion protocol. The mandatory
        # supplemental steps execute the real historical/current control suites.
        suites = {row['module']: row['tests'] for row in cls.supplemental_roster['suites']}
        def isolated_discovery(loader, start_dir, pattern='test*.py', top_level_dir=None):
            return unittest.TestSuite(named_fixture(name) for name in suites[Path(pattern).stem])
        with mock.patch.object(unittest.TestLoader, 'discover', isolated_discovery):
            for row in cls.supplemental_roster['suites']:
                report = supplemental.run_suite(ROOT, row['suite'], stream=io.StringIO())
                if report['all_named_controls_passed'] is not True:
                    raise ValueError('isolated supplemental completion failed')
                cls.reports[supplemental.OUTPUTS[row['suite']]] = report

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
        (root / supplemental.ROSTER).write_bytes(self.supplemental_roster_bytes)
        (out / supplemental.RETAINED_ROSTER).write_bytes(self.supplemental_roster_bytes)
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
            'W1_QROM_STEP_RESULTS': json.dumps(steps),
            'W1_QROM_CURRENT_STEP_RESULTS': json.dumps(steps), 'SOURCE_KIND': 'head',
            'EXPECTED_SOURCE': HEAD, 'EXPECTED_HEAD': HEAD, 'EXPECTED_BASE': BASE,
        }
        stdout, stderr = io.StringIO(), io.StringIO()
        exit_code = 0
        # The scope gate reconstructs observations from the actual checkout;
        # only retained report files are replaced by each isolated mutation.
        source_root = ROOT if step in ('report_scopes', 'status') else root
        with working_directory(source_root), mock.patch.object(sys, 'argv', ['gate', str(out)]), \
                mock.patch.dict(os.environ, environment), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                if step == 'status':
                    # Call the same production CLI selected by the exact workflow
                    # command above; no test-side reconstruction of verify logic.
                    argv = ['w1_qrom_current_ci.py', 'verify', '--repo-root', str(ROOT),
                            '--out', str(out), '--kind', 'head', '--expected-source', HEAD,
                            '--expected-head', HEAD, '--expected-base', BASE]
                    with mock.patch.object(sys, 'argv', argv):
                        exit_code = current_ci.main()
                else:
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

    def completed_workspace(self, *, status=False):
        root, out = self.workspace()
        if status:
            # The current final gate has its own receipt namespace and nested
            # supplemental records. These inert named cases isolate completion
            # validation; they are never reported as scientific test execution.
            (out / 'required-tests.json').write_bytes(self.current_roster_bytes)
            suites = {row['module']: row['tests'] for row in self.current_roster['suites']}
            def isolated_discovery(loader, start_dir, pattern='test*.py', top_level_dir=None):
                return unittest.TestSuite(named_fixture(name) for name in suites[Path(pattern).stem])
            with mock.patch.object(unittest.TestLoader, 'discover', isolated_discovery):
                named = current_ci.execute_named(ROOT, self.current_roster, io.StringIO())
            current_ci.validate_named(named, self.current_roster)
            write_json(out / 'named-tests.json', named)
            write_json(out / 'implementation.json', self.reports['implementation-current.json'])
            write_json(out / 'historical-drift.json', self.current_drift)
            (out / 'historical-on-current.stdout.log').write_bytes(self.drift_stdout)
            (out / 'historical-on-current.stderr.log').write_bytes(self.drift_stderr)
            supplemental_out = out / 'supplemental'
            supplemental_out.mkdir()
            (supplemental_out / supplemental.RETAINED_ROSTER).write_bytes(
                self.supplemental_roster_bytes)
            for name in supplemental.OUTPUTS.values():
                write_json(supplemental_out / name, self.reports[name])
        else:
            result = self.run_named(root, out)
            self.assertEqual(result[0], 0, result[2])
        self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], True)
        return root, out

    def run_supplemental(self, root, mode):
        row = self.supplemental_roster['suites'][0]
        module = row['module']
        directory = root / 'scripts/ci'
        directory.mkdir(parents=True, exist_ok=True)
        if mode == 'import_exit_zero':
            (directory / (module + '.py')).write_text('raise SystemExit(0)\n')
        elif mode == 'load_tests_exit_zero':
            (directory / (module + '.py')).write_text(
                'def load_tests(loader, standard_tests, pattern):\n    raise SystemExit(0)\n')
        discover = unittest.TestLoader.discover
        def isolated_discovery(loader, start_dir, pattern='test*.py', top_level_dir=None):
            if mode in ('import_exit_zero', 'load_tests_exit_zero'):
                return discover(loader, start_dir, pattern, top_level_dir)
            names = list(row['tests'])
            if mode == 'no_tests':
                names.clear()
            elif mode == 'duplicate':
                names.append(names[0])
            return unittest.TestSuite(named_fixture(name, mode == 'skip') for name in names)
        cached = sys.modules.pop(module, None)
        try:
            with mock.patch.object(sys, 'path', [str(directory)] + list(sys.path)), \
                    mock.patch.object(unittest.TestLoader, 'discover', isolated_discovery):
                return supplemental.run_suite(root, 'historical', stream=io.StringIO())
        finally:
            sys.modules.pop(module, None)
            if cached is not None:
                sys.modules[module] = cached

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
        report = self.run_supplemental(root, 'import_exit_zero')
        self.assertIs(report['all_named_controls_passed'], False)
        self.assertIn('SystemExit', report['exception'] + '\n'.join(report['loader_errors']))

    def test_named_load_tests_system_exit_zero_is_rejected(self):
        root, out = self.workspace()
        result = self.run_named(root, out, 'load_tests_exit_zero')
        self.assertNotEqual(result[0], 0, 'load_tests SystemExit(0) must not complete the roster')
        self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], False)
        report = self.run_supplemental(root, 'load_tests_exit_zero')
        self.assertIs(report['all_named_controls_passed'], False)
        self.assertIn('SystemExit', report['exception'])

    def test_named_missing_duplicate_and_skipped_controls_are_rejected(self):
        for mode in ('missing', 'duplicate', 'skip'):
            with self.subTest(mode=mode):
                root, out = self.workspace()
                result = self.run_named(root, out, mode)
                self.assertNotEqual(result[0], 0)
                self.assertIs(read_json(out / 'named-tests.json')['all_named_controls_passed'], False)
        for mode in ('no_tests', 'duplicate', 'skip'):
            with self.subTest(supplemental=mode):
                root, _ = self.workspace()
                report = self.run_supplemental(root, mode)
                self.assertIs(report['all_named_controls_passed'], False)

    def test_status_rejects_exit_zero_without_named_completion(self):
        for name in ('named-tests.json', *supplemental.OUTPUTS.values()):
            with self.subTest(completion=name):
                root, out = self.completed_workspace(status=True)
                target = out / name if name == 'named-tests.json' else out / 'supplemental' / name
                target.unlink()  # All other evidence and step successes remain.
                result = self.execute('status', root, out)
                self.assertNotEqual(result[0], 0, 'successful steps cannot replace a completion record')
                self.assertIs(read_json(out / 'current-ci-status.json')['all_required_current_observations_passed'], False)

    def test_status_independently_rechecks_named_ids_and_boolean_scope(self):
        for mutation in ('missing_success', 'duplicate_success', 'skip', 'scope_zero', 'passed_one'):
            with self.subTest(mutation=mutation):
                root, out = self.completed_workspace(status=True)
                report = read_json(out / 'named-tests.json')
                first = report['suites'][0]
                if mutation == 'missing_success':
                    first['success_ids'].pop()
                elif mutation == 'duplicate_success':
                    first['success_ids'].append(first['success_ids'][0])
                elif mutation == 'skip':
                    first['skipped'] = [[first['expected_ids'][0], 'retained skipped control']]
                elif mutation == 'scope_zero':
                    report['qualification']['post_quantum_soundness_qualified'] = 0
                else:
                    report['all_named_controls_passed'] = 1
                write_json(out / 'named-tests.json', report)
                result = self.execute('status', root, out)
                self.assertNotEqual(result[0], 0)
                self.assertIs(read_json(out / 'current-ci-status.json')['all_required_current_observations_passed'], False)
        for suite in supplemental.OUTPUTS:
            with self.subTest(supplemental=suite):
                root, out = self.completed_workspace(status=True)
                path = out / 'supplemental' / supplemental.OUTPUTS[suite]
                report = read_json(path)
                report['success_ids'].pop()
                write_json(path, report)
                result = self.execute('status', root, out)
                self.assertNotEqual(result[0], 0)
                status_report = read_json(out / 'current-ci-status.json')
                self.assertEqual(status_report['identities'], {})
                self.assertTrue(any('supplemental' in reason
                                    for reason in status_report['validation_errors']))

    def test_status_requires_every_step_outcome_and_conclusion(self):
        root, out = self.completed_workspace(status=True)
        positive = self.execute('status', root, out)
        self.assertEqual(positive[0], 0, positive[2])
        self.assertIs(read_json(out / 'current-ci-status.json')['all_required_current_observations_passed'], True)
        for stage in REQUIRED_STAGES:
            for field, value in (('outcome', 'failure'), ('conclusion', 'skipped')):
                with self.subTest(stage=stage, field=field):
                    root, out = self.completed_workspace(status=True)
                    steps = {name: {'outcome': 'success', 'conclusion': 'success'}
                             for name in REQUIRED_STAGES}
                    steps[stage][field] = value
                    result = self.execute('status', root, out, steps=steps)
                    self.assertNotEqual(result[0], 0)
                    status = read_json(out / 'current-ci-status.json')
                    self.assertIn(stage, status['failed_or_skipped_stages'])
                    self.assertIs(status['all_required_current_observations_passed'], False)

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

        def relabel_historical(reports):
            reports['historical-source.json']['historical_source_commit'] = 'a' * 40

        def promote_historical_to_current(reports):
            reports['historical-source.json']['current_project_mapping'] = True

        def wrong_git_mode(reports):
            reports['historical-source.json']['project_files'][0]['git_mode'] = '120000'

        def replaced_git_blob(reports):
            reports['historical-source.json']['project_files'][0]['git_blob_oid'] = '0' * 40

        def changed_regular_git_mode(reports):
            row = reports['historical-source.json']['project_files'][0]
            row['git_mode'] = '100755' if row['git_mode'] == '100644' else '100644'

        def mutually_relabelled_historical_sources(reports):
            for row in (reports['historical-source.json']['project_files'][0],
                        reports['implementation.json']['project_files'][0]):
                row.update(path='unreviewed-source.rs', bytes=1, sha256='0' * 64)

        def replace_refusal_with_success(reports):
            reports['current-v1-refusal.json']['result'] = 'MAPPING_REPRODUCED_SECURITY_HOLD'

        def remove_refusal(reports):
            del reports['current-v1-refusal.json']

        def remove_current_mapping(reports):
            del reports['implementation-current.json']

        def historical_report_as_current(reports):
            reports['implementation-current.json'] = deepcopy(reports['implementation.json'])

        def promote_current_mapping(reports):
            reports['implementation-current.json']['qualification']['quantum_work_qualified'] = True

        def refuse_as_zero(reports):
            reports['current-v1-refusal.json']['current_source_mapping_performed'] = 0

        def incomplete_current_closure(reports):
            reports['implementation-current.json']['local_path_closure']['files'].pop()

        def replaced_current_revision(reports):
            reports['implementation-current.json']['source_base_commit'] = '0' * 40

        def replaced_current_contract(reports):
            reports['implementation-current.json']['contract_sha256'] = '0' * 64

        def replaced_current_closure(reports):
            closure = reports['implementation-current.json']['local_path_closure']
            closure['files'] = [{'path': 'unreviewed-source.rs', 'bytes': 1, 'sha256': '0' * 64}]
            closure['source_files_checked'] = 1

        def missing_supplemental_completion(reports):
            del reports[supplemental.OUTPUTS['historical']]

        def skipped_supplemental_control(reports):
            report = reports[supplemental.OUTPUTS['current']]
            report['skipped'] = [[report['expected_ids'][0], 'skipped control']]

        for mutation in (true_implementation, zero_qualification, inferred_bits, full_theorem,
                         latest_revision, relabel_historical, promote_historical_to_current,
                         wrong_git_mode, replaced_git_blob, changed_regular_git_mode,
                         mutually_relabelled_historical_sources,
                         replace_refusal_with_success, remove_refusal,
                         remove_current_mapping, historical_report_as_current,
                         promote_current_mapping, refuse_as_zero, incomplete_current_closure,
                         replaced_current_revision, replaced_current_contract, replaced_current_closure,
                         missing_supplemental_completion, skipped_supplemental_control):
            with self.subTest(mutation=mutation.__name__):
                self.assert_scope_rejected(mutation)


if __name__ == '__main__':
    unittest.main()
