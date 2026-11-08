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

import w1_qrom_closure_controls as gate


def workflow_run_body(workflow, step_id):
    """Extract the actual reviewed YAML block; fail on an ambiguous layout."""
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


class ClosureControlsTests(unittest.TestCase):
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
            'schema': 'TRNM-W1-QROM-CLOSURE-REQUIRED-TESTS1',
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


class ClosureWorkflowCompletionTests(unittest.TestCase):
    """Run the real shell blocks against isolated, honestly identified fixtures.

    The source verifier and named runner execute for real in a small temporary
    Git repository. Its six tiny test modules avoid recursively running this
    scientific roster. GitHub step outcomes are test inputs to the consumer;
    they do not certify any main-repository source, preflight or scientific run.
    No archived source or project report is replaced by a successful stub.
    """

    REQUIRED_STAGES = ('observations', 'checkout', 'source_before', 'preflight',
                       'named_controls', 'reproduce', 'source_after')

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
        (directory / 'w1_qrom_closure_controls.py').write_bytes(self.controls_bytes)
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
        roster = {'schema': 'TRNM-W1-QROM-CLOSURE-REQUIRED-TESTS1',
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
        out = self.temp / 'w1-qrom-closure-head-123-1'
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


if __name__ == '__main__':
    unittest.main()
