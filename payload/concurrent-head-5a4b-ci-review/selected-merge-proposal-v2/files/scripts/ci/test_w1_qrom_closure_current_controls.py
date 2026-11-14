"""Adversarial completion-gate controls, including a real load_tests exit(0)."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
import uuid

import w1_qrom_closure_current_controls as gate


def workflow_run_body(workflow, step_id):
    """Extract the actual reviewed YAML block; fail on an ambiguous layout."""
    workflow = workflow.split('  closure:\n', 1)[1]
    lines = workflow.splitlines()
    markers = [i for i, line in enumerate(lines)
               if line == '        id: ' + step_id]
    if len(markers) != 1:
        raise ValueError('expected one workflow step: ' + step_id)
    start = markers[0]
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith('      - name:')), len(lines))
    block = lines[start:end]
    openers = [i for i, line in enumerate(block) if line == '        run: |']
    if len(openers) != 1:
        raise ValueError('expected one literal run body: ' + step_id)
    body = block[openers[0] + 1:]
    if not body or any(line and not line.startswith('          ') for line in body):
        raise ValueError('unexpected workflow run indentation: ' + step_id)
    return textwrap.dedent('\n'.join(body)) + '\n'


class CurrentClosureControlsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out = self.root / 'observations'
        self.out.mkdir()
        (self.root / 'scripts/ci').mkdir(parents=True)
        (self.root / 'config/pon').mkdir(parents=True)
        self.module = 'test_w1_closure_fixture_' + uuid.uuid4().hex
        self.source = self.root / 'scripts/ci' / (self.module + '.py')
        self.source.write_text('import unittest\nclass Probe(unittest.TestCase):\n'
                               '    def test_one(self):\n        self.assertEqual(2 + 3, 5)\n')
        self.roster = {
            'schema': 'TRNM-W1-QROM-CLOSURE-CURRENT-REQUIRED-TESTS2',
            'suites': [{'module': self.module, 'tests': [self.module + '.Probe.test_one']}],
            'expected_tests': 1, 'qualification': dict(gate.QUALIFICATION),
        }
        self.digest = self.save_roster()
        patch = mock.patch.object(gate, 'MODULES', (self.module,))
        patch.start()
        self.addCleanup(patch.stop)
        previous_path = list(sys.path)
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), previous_path))
        self.addCleanup(lambda: sys.modules.pop(self.module, None))

    def save_roster(self):
        raw = (json.dumps(self.roster, sort_keys=True, indent=2) + '\n').encode()
        (self.root / gate.ROSTER).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def execute(self):
        with contextlib.redirect_stderr(io.StringIO()):
            return gate.run(self.root, self.out, self.digest)

    def alter(self, mutation):
        value = self.execute()
        mutation(value)
        (self.out / 'named-controls.json').write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            gate.check(self.root, self.out, self.digest)

    def test_complete_actual_named_test_accepted_without_qualification(self):
        self.execute()
        value = gate.check(self.root, self.out, self.digest)
        self.assertEqual(value['suites'][0]['tests_run'], 1)
        self.assertEqual(value['suites'][0]['success_ids'], self.roster['suites'][0]['tests'])
        self.assertIs(value['qualification']['post_quantum_soundness_qualified'], False)
        self.assertIsNone(value['qualification']['unconditional_project_security_bits'])

    def test_missing_completion_after_zero_exit_is_refused(self):
        with self.assertRaises(OSError):
            gate.check(self.root, self.out, self.digest)

    def test_real_load_tests_system_exit_zero_is_refused(self):
        with self.source.open('a') as stream:
            stream.write('\ndef load_tests(loader, tests, pattern):\n    raise SystemExit(0)\n')
        with self.assertRaises(ValueError):
            self.execute()
        value = json.loads((self.out / 'named-controls.json').read_text())
        self.assertEqual(value['suites'][0]['exception'], 'SystemExit: 0')
        self.assertEqual(value['suites'][0]['tests_run'], 0)
        with self.assertRaises(ValueError):
            gate.check(self.root, self.out, self.digest)

    def test_unregistered_required_test_is_refused(self):
        self.roster['suites'][0]['tests'] = [self.module + '.Probe.test_missing']
        self.digest = self.save_roster()
        with self.assertRaises(ValueError):
            self.execute()

    def test_extra_unreviewed_actual_test_is_refused(self):
        with self.source.open('a') as stream:
            stream.write('    def test_extra(self):\n        pass\n')
        with self.assertRaises(ValueError):
            self.execute()

    def test_skipped_actual_test_is_refused(self):
        self.source.write_text('import unittest\nclass Probe(unittest.TestCase):\n'
                               '    @unittest.skip("probe")\n    def test_one(self):\n        pass\n')
        with self.assertRaises(ValueError):
            self.execute()

    def test_expected_failure_actual_test_is_refused(self):
        self.source.write_text('import unittest\nclass Probe(unittest.TestCase):\n'
                               '    @unittest.expectedFailure\n    def test_one(self):\n        self.fail("probe")\n')
        with self.assertRaises(ValueError):
            self.execute()

    def test_duplicate_success_cannot_replace_missing_started_id(self):
        def mutation(value):
            value['suites'][0]['success_ids'] *= 2
            value['suites'][0]['started_ids'] = []
        self.alter(mutation)

    def test_boolean_test_count_is_refused(self):
        self.alter(lambda value: value['suites'][0].__setitem__('tests_run', True))

    def test_empty_completion_suites_are_refused(self):
        self.alter(lambda value: value.__setitem__('suites', []))

    def test_scope_upgrade_is_refused(self):
        self.alter(lambda value: value['qualification'].__setitem__('post_quantum_soundness_qualified', True))

    def test_roster_drift_is_refused_before_execution(self):
        with (self.root / gate.ROSTER).open('a') as stream:
            stream.write(' ')
        with self.assertRaisesRegex(ValueError, 'roster digest changed'):
            self.execute()

    def test_completion_overwrite_is_refused(self):
        self.execute()
        before = (self.out / 'named-controls.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'refusing to replace'):
            self.execute()
        self.assertEqual((self.out / 'named-controls.json').read_bytes(), before)

    def test_duplicate_and_nonfinite_json_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                gate.strict_json(raw)


class CurrentClosureWorkflowCompletionTests(unittest.TestCase):
    """Run the real shell blocks against isolated, honestly identified fixtures.

    The source verifier and named runner execute for real in a small temporary
    Git repository. Its six tiny test modules avoid recursively running this
    scientific roster. GitHub step outcomes are test inputs to the consumer;
    they do not certify any main-repository source, preflight or scientific run.
    No archived source or project report is replaced by a successful stub.
    """

    REQUIRED_STAGES = ('observations', 'checkout', 'source_before', 'preflight',
                       'named_controls', 'historical_refusal', 'reproduce', 'source_after')

    @classmethod
    def setUpClass(cls):
        cls.repository = Path(__file__).resolve().parents[2]
        cls.workflow_bytes = (cls.repository / '.github/workflows/pon-w1-qrom-closure.yml').read_bytes()
        cls.blocks = {name: workflow_run_body(cls.workflow_bytes.decode(), name)
                      for name in ('observations', 'source_before', 'named_controls',
                                   'source_after', 'completion')}
        cls.controls_bytes = Path(gate.__file__).read_bytes()
        cls.verifier_bytes = (cls.repository / 'scripts/ci/verify_ci_source.py').read_bytes()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='w1-closure-workflow-')
        self.addCleanup(self.temporary.cleanup)
        self.temp = Path(self.temporary.name)
        self.fixture_count = 0

    def invoke(self, command, root, environment):
        return subprocess.run(command, cwd=root, env=environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def fixture(self, kind='head'):
        self.fixture_count += 1
        root = self.temp / ('source-' + str(self.fixture_count))
        out = self.temp / ('observations-' + str(self.fixture_count))
        root.mkdir()
        out.mkdir()
        directory = root / 'scripts/ci'
        directory.mkdir(parents=True)
        (directory / 'w1_qrom_closure_current_controls.py').write_bytes(self.controls_bytes)
        (directory / 'verify_ci_source.py').write_bytes(self.verifier_bytes)
        workflow_path = root / '.github/workflows/pon-w1-qrom-closure.yml'
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_bytes(self.workflow_bytes)
        rows = []
        for module in gate.MODULES:
            (directory / (module + '.py')).write_text(
                'import unittest\nclass Probe(unittest.TestCase):\n'
                '    def test_observed(self):\n        self.assertEqual(2 + 3, 5)\n')
            rows.append({'module': module, 'tests': [module + '.Probe.test_observed']})
        roster = {'schema': 'TRNM-W1-QROM-CLOSURE-CURRENT-REQUIRED-TESTS2',
                  'suites': rows, 'expected_tests': len(rows),
                  'qualification': dict(gate.QUALIFICATION)}
        raw = (json.dumps(roster, indent=2, sort_keys=True) + '\n').encode()
        roster_path = root / gate.ROSTER
        roster_path.parent.mkdir(parents=True)
        roster_path.write_bytes(raw)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('GIT_')}
        environment.update(PYTHONDONTWRITEBYTECODE='1', GIT_CONFIG_NOSYSTEM='1',
                           GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM='1',
                           GIT_TERMINAL_PROMPT='0')

        def git(*args):
            result = self.invoke(
                ['git', '-c', 'user.name=Closure fixture',
                 '-c', 'user.email=closure-fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + os.devnull,
                 '-c', 'core.autocrlf=false', *args], root, environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout.strip()

        git('init', '--quiet', '--template=', '--initial-branch=source')
        git('add', '.')
        git('commit', '--quiet', '-m', 'isolated completion fixture')
        expected_base = expected_head = git('rev-parse', 'HEAD')
        if kind == 'prospective-merge':
            git('checkout', '--quiet', '-b', 'candidate')
            (root / 'candidate-marker.txt').write_text('candidate source fixture\n')
            git('add', 'candidate-marker.txt')
            git('commit', '--quiet', '-m', 'fixture candidate')
            expected_head = git('rev-parse', 'HEAD')
            git('checkout', '--quiet', 'source')
            (root / 'base-marker.txt').write_text('base source fixture\n')
            git('add', 'base-marker.txt')
            git('commit', '--quiet', '-m', 'fixture base')
            expected_base = git('rev-parse', 'HEAD')
            git('merge', '--quiet', '--no-ff', '-m', 'fixture prospective merge', 'candidate')
        else:
            self.assertEqual(kind, 'head')
        environment.update(
            W1_CLOSURE_OUT=str(out), W1_CLOSURE_ROSTER_SHA256=hashlib.sha256(raw).hexdigest(),
            SOURCE_KIND=kind, EXPECTED_HEAD=expected_head, EXPECTED_BASE=expected_base,
            EXPECTED_SOURCE=git('rev-parse', 'HEAD'))
        for stage in ('source_before', 'named_controls', 'source_after'):
            result = self.invoke(['bash', '-c', self.blocks[stage]], root, environment)
            self.assertEqual(result.returncode, 0, stage + ': ' + result.stdout + result.stderr)
        before = json.loads((out / 'source-before.json').read_text())
        after = json.loads((out / 'source-after.json').read_text())
        self.assertEqual(before, after)
        self.assertIs(before['tracked_worktree_verified'], True)
        self.assertEqual(before['tested_commit'], environment['EXPECTED_SOURCE'])
        self.assertIs(before['tests_executed_by_identity_check'], False)
        # Explicitly synthetic final-consumer inputs, not project evidence.
        (out / 'lifetime-current.json').write_text(json.dumps({
            'schema': 'TRNM-W1-LIFETIME-CURRENT-OBSERVATION2',
            'status': 'CURRENT_SELECTED_SOURCE_OBSERVED_SECURITY_HOLD',
            'qualification': {'production_activation': False, 'consensus_admission': False,
                'whole_chain_post_quantum_qualified': False, 'actual_lifetime_failure_bound': None,
                'coverage_exhaustiveness_proved': False, 'composition_theorem_instantiated': False}}))
        (out / 'historical-refusal.json').write_text(json.dumps({
            'schema': 'TRNM-W1-LIFETIME-HISTORICAL-CURRENT-REFUSAL2',
            'expected_source': environment['EXPECTED_SOURCE'], 'exit_code': 2,
            'historical_pins_relaxed': False,
            'historical_refusal': {'status': 'REFUSED', 'error': 'source identity mismatch: explicit isolated fixture'}}))
        return root, out, environment

    def complete(self, fixture, *, steps=None, raw_steps=None, environment_update=None):
        root, out, baseline = fixture
        environment = dict(baseline)
        if steps is None:
            steps = {name: {'outcome': 'success', 'conclusion': 'success'}
                     for name in self.REQUIRED_STAGES}
        environment['W1_CLOSURE_STEPS'] = json.dumps(steps) if raw_steps is None else raw_steps
        environment.update(environment_update or {})
        return self.invoke(['bash', '-c', self.blocks['completion']], root, environment)

    def clear_status(self, fixture):
        (fixture[1] / 'ci-status.json').unlink(missing_ok=True)

    def assert_failed_completion(self, result, fixture):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('All fixed named observations completed;', result.stdout)
        status_path = fixture[1] / 'ci-status.json'
        if status_path.exists():
            status = json.loads(status_path.read_text())
            self.assertIs(status['all_required_observations_passed'], False)
            self.assertEqual(status['qualification'], gate.QUALIFICATION)

    def test_workflow_real_fixture_completion_retains_unqualified_scope(self):
        for kind in ('head', 'prospective-merge'):
            with self.subTest(kind=kind):
                fixture = self.fixture(kind)
                result = self.complete(fixture)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                status = json.loads((fixture[1] / 'ci-status.json').read_text())
                self.assertIs(status['all_required_observations_passed'], True)
                self.assertEqual(status['qualification'], gate.QUALIFICATION)
                self.assertIsNone(status['qualification']['unconditional_project_security_bits'])
                self.assertEqual(status['expected_source'], fixture[2]['EXPECTED_SOURCE'])
                named = json.loads((fixture[1] / 'named-controls.json').read_text())
                self.assertEqual(named['required_tests'], len(gate.MODULES))
                self.assertEqual(sum(row['tests_run'] for row in named['suites']), len(gate.MODULES))

    def test_workflow_matching_record_cannot_mask_failed_or_missing_stage(self):
        fixture = self.fixture()
        for name in self.REQUIRED_STAGES:
            for state in ('missing', 'failure', 'skipped', 'softened_failure'):
                with self.subTest(stage=name, state=state):
                    steps = {stage: {'outcome': 'success', 'conclusion': 'success'}
                             for stage in self.REQUIRED_STAGES}
                    if state == 'missing':
                        del steps[name]
                    elif state == 'softened_failure':
                        steps[name]['outcome'] = 'failure'
                    else:
                        steps[name]['conclusion'] = state
                    self.clear_status(fixture)
                    result = self.complete(fixture, steps=steps)
                    self.assert_failed_completion(result, fixture)
                    status = json.loads((fixture[1] / 'ci-status.json').read_text())
                    self.assertIn(name, status['failed_or_skipped_stages'])
                    self.assertIsNone(status['completion_or_identity_error'])

    def test_workflow_zero_exit_without_named_completion_is_refused(self):
        fixture = self.fixture()
        (fixture[1] / 'named-controls.json').unlink()
        exit_zero = self.invoke([sys.executable, '-c', 'raise SystemExit(0)'], fixture[0], fixture[2])
        self.assertEqual(exit_zero.returncode, 0)
        result = self.complete(fixture)
        self.assert_failed_completion(result, fixture)
        status = json.loads((fixture[1] / 'ci-status.json').read_text())
        self.assertIn('FileNotFoundError', status['completion_or_identity_error'])

    def test_workflow_source_identity_remains_strict_under_optimization(self):
        for kind in ('head', 'prospective-merge'):
            fixture = self.fixture(kind)
            before_path = fixture[1] / 'source-before.json'
            after_path = fixture[1] / 'source-after.json'
            baseline = json.loads(before_path.read_text())
            changes = [('schema', 'wrong'), ('kind', 'wrong'),
                       ('tracked_worktree_verified', False), ('tracked_entries', True),
                       ('tracked_entries', 0), ('tested_commit', '0' * 40),
                       ('candidate', '0' * 40), ('base', '0' * 40),
                       ('prospective_merge', '0' * 40), ('only_after_tree', '0' * 40)]
            for field, value in changes:
                with self.subTest(kind=kind, field=field, value=value):
                    before, after = dict(baseline), dict(baseline)
                    if field == 'only_after_tree':
                        after['tested_tree'] = value
                    else:
                        before[field] = after[field] = value
                    before_path.write_text(json.dumps(before))
                    after_path.write_text(json.dumps(after))
                    self.clear_status(fixture)
                    result = self.complete(fixture, environment_update={'PYTHONOPTIMIZE': '1'})
                    self.assert_failed_completion(result, fixture)
                    status = json.loads((fixture[1] / 'ci-status.json').read_text())
                    self.assertIsNotNone(status['completion_or_identity_error'])

    def test_workflow_final_status_cannot_overwrite_an_old_completion(self):
        fixture = self.fixture()
        first = self.complete(fixture)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        status_path = fixture[1] / 'ci-status.json'
        retained = status_path.read_bytes()
        second = self.complete(fixture)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn('FileExistsError', second.stdout + second.stderr)
        self.assertEqual(status_path.read_bytes(), retained)

    def test_workflow_reserves_a_fresh_directory_without_reuse(self):
        environment = dict(os.environ)
        environment.update(RUNNER_TEMP=str(self.temp), SOURCE_KIND='head',
                           GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                           GITHUB_ENV=str(self.temp / 'github-env'))
        command = ['bash', '-c', self.blocks['observations']]
        first = self.invoke(command, self.temp, environment)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        out = self.temp / 'w1-qrom-current-closure-head-123-1'
        self.assertTrue((out / 'SCOPE.txt').is_file())
        (out / 'named-controls.json').write_text('retained old record\n')
        original_environment = (self.temp / 'github-env').read_bytes()
        second = self.invoke(command, self.temp, environment)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((out / 'named-controls.json').read_text(), 'retained old record\n')
        self.assertEqual((self.temp / 'github-env').read_bytes(), original_environment)

    def test_workflow_malformed_consumed_json_is_refused(self):
        fixture = self.fixture()
        named_path = fixture[1] / 'named-controls.json'
        named_baseline = named_path.read_bytes()
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '[]', 'null', 'true'):
            with self.subTest(input='steps', raw=raw):
                self.clear_status(fixture)
                result = self.complete(fixture, raw_steps=raw)
                self.assert_failed_completion(result, fixture)
                self.assertTrue((fixture[1] / 'completion.log').read_text())
            with self.subTest(input='named', raw=raw):
                named_path.write_text(raw)
                self.clear_status(fixture)
                result = self.complete(fixture)
                self.assert_failed_completion(result, fixture)
                self.assertTrue((fixture[1] / 'completion.log').read_text())
                named_path.write_bytes(named_baseline)


    def test_current_lifetime_or_refusal_scope_drift_cannot_pass_completion(self):
        for filename, field, changed in (
                ('lifetime-current.json', 'schema', 'TRNM-W1-LIFETIME-LEDGER-REPORT1'),
                ('lifetime-current.json', 'status', 'QUALIFIED'),
                ('historical-refusal.json', 'exit_code', 0),
                ('historical-refusal.json', 'exit_code', True),
                ('historical-refusal.json', 'expected_source', '0' * 40),
                ('historical-refusal.json', 'historical_pins_relaxed', True)):
            fixture = self.fixture()
            path = fixture[1] / filename
            value = json.loads(path.read_text())
            value[field] = changed
            path.write_text(json.dumps(value))
            self.assert_failed_completion(self.complete(fixture), fixture)
        fixture = self.fixture()
        path = fixture[1] / 'lifetime-current.json'
        value = json.loads(path.read_text())
        value['qualification']['actual_lifetime_failure_bound'] = 0
        path.write_text(json.dumps(value))
        self.assert_failed_completion(self.complete(fixture), fixture)

    def test_current_workflow_keeps_historical_fixed_source_and_original_roster(self):
        text = self.workflow_bytes.decode()
        historical, current = text.split('  closure-historical:\n', 1)[1].split('  closure:\n', 1)
        self.assertIn('EXPECTED_SOURCE: 1a14f7d4826363daefac9ec10131c66d7e70ece7', historical)
        self.assertIn('EXPECTED_HEAD: 1a14f7d4826363daefac9ec10131c66d7e70ece7', historical)
        self.assertNotIn('matrix.source', historical)
        self.assertIn('scripts/ci/w1_qrom_closure_controls.py run', historical)
        self.assertIn('cmp evidence/pon-w1-lifetime-20261107/project-report.json', historical)
        self.assertIn('source: [head, prospective-merge]', current)
        self.assertIn('scripts/ci/w1_qrom_closure_current_controls.py run', current)
        self.assertIn('python3 scripts/w1_lifetime_current_observation.py --input', current)
        self.assertIn('python3 tests/fixtures/w1-lifetime-historical-7150/ledger.py --root . --input', current)
        self.assertNotIn('python3 scripts/w1_lifetime_ledger.py --input', current)
        self.assertNotIn('cmp evidence/pon-w1-lifetime-20261107/project-report.json', current)
        self.assertIn('test \"$code\" -eq 2', current)
        self.assertIn('source identity mismatch: ', current)
        self.assertIn('check-semantics --output', current)
        self.assertNotIn('cmp evidence/pon-w1-qrom-semantics-20261107/report.json', current)
        self.assertIn('cmp evidence/pon-w1-qrom-semantics-20261107/report.json', historical)
        path = self.repository / 'config/pon/w1-qrom-closure-required-tests-v1.json'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         'ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f')



    def test_current_roster_digest_matches_workflow_and_preserves_distinct_namespace(self):
        raw = (self.repository / gate.ROSTER).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        current = self.workflow_bytes.decode().split('  closure:\n', 1)[1]
        self.assertIn('W1_CLOSURE_ROSTER_SHA256: ' + digest, current)
        roster = gate.load_roster(self.repository, digest)
        self.assertEqual(roster['schema'], 'TRNM-W1-QROM-CLOSURE-CURRENT-REQUIRED-TESTS2')
        self.assertNotIn('test_w1_lifetime_ledger', gate.MODULES)
        self.assertIn('test_w1_lifetime_current_observation', gate.MODULES)
        self.assertIn('test_w1_qrom_closure_current_controls', gate.MODULES)
        self.assertNotEqual(digest, 'ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f')



class CurrentSemanticsCorrespondenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository = Path(__file__).resolve().parents[2]
        cls.generated = tempfile.TemporaryDirectory(prefix='semantics-current-actual-')
        cls.addClassCleanup(cls.generated.cleanup)
        target = Path(cls.generated.name) / 'actual.json'
        child = subprocess.run([sys.executable, str(cls.repository / 'scripts/w1_qrom_semantics_audit.py'),
                                '--out', str(target)], cwd=cls.repository,
                               capture_output=True, text=True, timeout=60, check=False)
        if child.returncode != 0:
            raise ValueError('actual semantics observation failed: ' + child.stderr)
        cls.actual_bytes = target.read_bytes()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='semantics-correspondence-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in (gate.HISTORICAL_SEMANTICS,
                     *(row[1] for row in gate.REVIEWED_LOCK_CHANGES)):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.repository / name).read_bytes())
        self.current = self.root / 'current.json'
        self.current.write_bytes(self.actual_bytes)

    def reject(self):
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            gate.check_semantics(self.root, self.current)

    def test_actual_report_has_only_the_reviewed_lock_provenance_delta(self):
        historical = (self.root / gate.HISTORICAL_SEMANTICS).read_bytes()
        result = gate.check_semantics(self.root, self.current)
        self.assertEqual(result['schema'], 'TRNM-W1-SEMANTICS-CURRENT-CORRESPONDENCE3')
        self.assertEqual(result['only_changed_json_pointers'], [
            '/provenance/lock_checks/0/sha256', '/provenance/lock_checks/2/sha256'])
        self.assertEqual([(row['path'], row['current_sha256'])
                          for row in result['reviewed_lock_changes']], [
            ('formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock',
             '93a68edce98e5c61e0cba33ebfbe392ff52df24633347da5a214ac8eb6eae24b'),
            ('formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock',
             'ed6ea70f20cbe45bf0bdef7f841adbdaa7c3b2a9838ffdfed64fa88f129b707a'),
        ])
        self.assertEqual(
            [(row['path'], row['historical_sha256'], row['current_sha256'])
             for row in result['reviewed_lock_changes']],
            [(path, old, current) for _, path, old, current in gate.REVIEWED_LOCK_CHANGES])
        self.assertTrue(result['all_other_report_fields_identical'])
        self.assertFalse(result['historical_report_bytes_rewritten'])
        self.assertFalse(result['new_native_execution_or_dependency_equivalence_proved'])
        self.assertEqual(result['qualification'], gate.QUALIFICATION)
        self.assertEqual((self.root / gate.HISTORICAL_SEMANTICS).read_bytes(), historical)

    def test_any_other_report_field_change_is_refused(self):
        for change in ('extra_claim', 'boolean_integer_alias', 'integer_float_alias'):
            with self.subTest(change=change):
                value = json.loads(self.actual_bytes)
                if change == 'extra_claim':
                    value['unreviewed_extra_claim'] = True
                elif change == 'boolean_integer_alias':
                    value['qualification']['end_to_end_qrom_bound_established'] = 0
                else:
                    value['guest_binary']['binary_bytes'] = float(
                        value['guest_binary']['binary_bytes'])
                self.current.write_text(json.dumps(value))
                self.reject()

    def test_missing_or_relabelled_reviewed_lock_entry_is_refused(self):
        for index in (0, 2):
            with self.subTest(index=index):
                value = json.loads(self.actual_bytes)
                value['provenance']['lock_checks'].pop(index)
                self.current.write_text(json.dumps(value))
                self.reject()
                value = json.loads(self.actual_bytes)
                value['provenance']['lock_checks'][index]['path'] = 'unrelated/Cargo.lock'
                self.current.write_text(json.dumps(value))
                self.reject()

    def test_changed_other_lock_sha_is_refused(self):
        for index in (0, 1, 2):
            with self.subTest(index=index):
                value = json.loads(self.actual_bytes)
                value['provenance']['lock_checks'][index]['sha256'] = '0' * 64
                self.current.write_text(json.dumps(value))
                self.reject()

    def test_changed_current_lock_bytes_cannot_be_relabelled_in_report(self):
        for index, name, _, _ in gate.REVIEWED_LOCK_CHANGES:
            with self.subTest(index=index):
                path = self.root / name
                original = path.read_bytes()
                changed = original + b'\n'
                try:
                    path.write_bytes(changed)
                    value = json.loads(self.actual_bytes)
                    value['provenance']['lock_checks'][index]['sha256'] = hashlib.sha256(changed).hexdigest()
                    self.current.write_text(json.dumps(value))
                    self.reject()
                finally:
                    path.write_bytes(original)
                    self.current.write_bytes(self.actual_bytes)

    def test_historical_report_bytes_are_frozen_even_for_json_whitespace(self):
        path = self.root / gate.HISTORICAL_SEMANTICS
        path.write_bytes(path.read_bytes() + b'\n')
        self.reject()

    def test_real_cli_accepts_actual_observation_and_rejects_scope_change(self):
        command = [sys.executable, str(self.repository / 'scripts/ci/w1_qrom_closure_current_controls.py'),
                   'check-semantics', '--root', str(self.root), '--output', str(self.current)]
        first = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)['schema'], 'TRNM-W1-SEMANTICS-CURRENT-CORRESPONDENCE3')
        value = json.loads(self.actual_bytes)
        value['unreviewed_extra_claim'] = True
        self.current.write_text(json.dumps(value))
        second = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(second.stdout, '')


if __name__ == '__main__':
    unittest.main()
