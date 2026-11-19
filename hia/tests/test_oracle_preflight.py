"""Run the real Oracle setup boundary in isolated Git checkouts.

Stop at the first compiler-source admission call. These controls exercise actual
preflight processes and retained failure bytes without claiming native execution.
"""
from __future__ import annotations

import json
import os
import subprocess
import unittest
from unittest.mock import patch

from hia.tests import test_oracle as oracle
from hia.tools import toolchain
from scripts.ci import test_project_boundary as boundary


class SourceAdmissionReached(RuntimeError):
    pass


class OraclePreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = boundary.ProjectBoundaryTests(
            'test_checkout_https_without_suffix_audits_detached_head')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.git('checkout', '--detach', self.fixture.head)

    def observe_setup(self, rejection=None):
        # A separate class keeps its class cleanup stack and partial evidence
        # independent of both the real Oracle suite and every other control.
        class SetupProbe(oracle.OracleNativeTests):
            pass

        output = self.fixture.root / 'oracle-evidence'
        environment = dict(self.fixture.env, HIA_ORACLE_OUTPUT=str(output))
        environment.pop('HIA_ORACLE_SETUP_PROBE', None)
        before = (self.fixture.git('show-ref'),
                  self.fixture.git('config', '--local', '--list'),
                  self.fixture.git('diff', 'HEAD'))
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(oracle, 'ROOT', self.fixture.root), \
                patch.object(toolchain, 'checked_source',
                             side_effect=SourceAdmissionReached('stop before compiler')) as gate:
            try:
                expected = SourceAdmissionReached if rejection is None else subprocess.CalledProcessError
                with self.assertRaises(expected):
                    SetupProbe.setUpClass()
                self.assertEqual(gate.call_count, 1 if rejection is None else 0)
            finally:
                SetupProbe.doClassCleanups()

        after = (self.fixture.git('show-ref'),
                 self.fixture.git('config', '--local', '--list'),
                 self.fixture.git('diff', 'HEAD'))
        self.assertEqual(before, after)
        self.assertEqual(self.fixture.git('branch', '--show-current'), '')
        report = json.loads((output / 'observations.json').read_text())
        self.assertEqual(report['result'], 'FAIL')
        self.assertFalse(report['finalized'])
        self.assertEqual(report['started_test_methods'], [])
        self.assertEqual(report['native_observations'], [])
        self.assertEqual(len(report['processes']), 1)
        process = report['processes'][0]
        self.assertEqual(process['stage'], 'project-preflight')
        self.assertEqual(process['timeout'], 20)
        stdout = (output / process['stdout']['path']).read_bytes()
        stderr = (output / process['stderr']['path']).read_bytes()
        if rejection is None:
            self.assertEqual(process['returncode'], 0, stderr)
            observed = json.loads(stdout)
            self.assertEqual(observed['result'], 'PASS')
            self.assertEqual(observed['mode'], '--audit')
            self.assertEqual(observed['branch'], '')
            self.assertIs(observed['remote_policy_mutated'], False)
            self.assertEqual(stderr, b'')
            self.assertIn('SourceAdmissionReached', report['setup_error'])
        else:
            self.assertEqual(process['returncode'], 2)
            self.assertEqual(process['failure_kind'], 'nonzero-exit')
            self.assertIn(rejection.encode(), stderr)
            self.assertNotIn(b'"result": "PASS"', stdout)
            self.assertIn('CalledProcessError', report['setup_error'])

    def test_detached_qualification_reaches_source_admission_without_mutating_git(self):
        self.observe_setup()

    def test_foreign_origin_refuses_before_compiler_and_preserves_stderr(self):
        self.fixture.git('remote', 'set-url', 'origin', boundary.HTTPS + '-fork.git')
        self.observe_setup('origin mismatch')

    def test_wrong_project_refuses_before_compiler_and_preserves_stderr(self):
        self.fixture.write('PROJECT_ID', 'other-project\n')
        self.observe_setup('project id mismatch')


if __name__ == '__main__':
    unittest.main()
