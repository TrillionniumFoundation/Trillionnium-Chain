#!/usr/bin/env python3
"""Run F0 preparation's actual preflight choice in detached Git fixtures.

Only the real boundary script runs. Source identity is separately fixture-bound
here; all compiler, native binary and service commands are forbidden.
"""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_fixed_host_root_f0 as runner
import test_project_boundary as boundary_controls


class F0PreparationPreflightControls(unittest.TestCase):
    def setUp(self):
        self.fixture = boundary_controls.ProjectBoundaryTests(
            methodName='test_detached_source_is_audit_only')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.git('checkout', '--detach', self.fixture.head)
        self.output = self.fixture.root / 'prepared-fixture'
        self.output.mkdir()
        self.args = SimpleNamespace(target_dir=self.fixture.root / 'target',
            expected_head=self.fixture.head,
            expected_tree=self.fixture.git('rev-parse', 'HEAD^{tree}'),
            cargo=Path('/forbidden-native/cargo'))
        self.commands = []

    def step(self, output, label, command, env, **_limits):
        self.commands.append((label, command))
        if label == 'preflight':
            self.assertEqual(command[:2], ['/bin/bash', 'scripts/project-preflight.sh'])
            result = subprocess.run(command, cwd=self.fixture.root, env=env,
                                    capture_output=True, timeout=10)
            (output / 'preflight.stdout.log').write_bytes(result.stdout)
            (output / 'preflight.stderr.log').write_bytes(result.stderr)
            return {'name': label, 'command': command, 'returncode': result.returncode,
                    'complete_success': result.returncode == 0}
        self.assertEqual(label, 'rustc-version', 'unexpected command before native barrier')
        self.assertEqual(command[0], '/forbidden-native/rustup')
        return {'name': label, 'command': command, 'returncode': None,
                'complete_success': False, 'native_execution_forbidden_by_control': True}

    def prepare(self, source_error=None):
        with (patch.object(runner, 'environment', return_value=dict(self.fixture.env)),
              patch.object(runner, 'resource_observation', return_value={'fixture': True}),
              patch.object(runner, 'exact_source', side_effect=source_error,
                           return_value={'name': 'source-before', 'complete_success': True}) as source,
              patch.object(runner, 'run_step', side_effect=self.step)):
            self.assertFalse(runner.prepare(self.args, self.output))
            source.assert_called_once()
        self.assertEqual(self.fixture.git('branch', '--show-current'), '')
        result = json.loads((self.output / 'prepared.json').read_text())
        self.assertFalse(result['prepared'])
        self.assertFalse(result['selector_invocation_attempted'])
        self.assertFalse((self.output / 'public_v3_multiprocess.bin').exists())
        return result

    def test_detached_prepare_passes_real_audit_and_stops_before_native(self):
        result = self.prepare()
        self.assertEqual(result['failure'], 'RUSTC-VERSION_FAILED')
        self.assertEqual([name for name, _ in self.commands], ['preflight', 'rustc-version'])
        report = json.loads((self.output / 'preflight.stdout.log').read_text())
        self.assertEqual((report['result'], report['mode'], report['branch']),
                         ('PASS', '--audit', ''))

    def test_audit_mode_does_not_rescue_a_foreign_repository(self):
        self.fixture.git('remote', 'set-url', 'origin', boundary_controls.HTTPS + '-fork.git')
        result = self.prepare()
        self.assertEqual(result['failure'], 'PREFLIGHT_FAILED')
        self.assertEqual([name for name, _ in self.commands], ['preflight'])
        self.assertIn('origin mismatch', (self.output / 'preflight.stderr.log').read_text())

    def test_source_failure_precedes_any_boundary_or_native_command(self):
        result = self.prepare(ValueError('RAW_SOURCE_IDENTITY_FAILED'))
        self.assertEqual(result['failure'], 'RAW_SOURCE_IDENTITY_FAILED')
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()
