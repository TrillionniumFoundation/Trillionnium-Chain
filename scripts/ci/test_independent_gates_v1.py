#!/usr/bin/env python3
"""Real child-process tests of outcome aggregation; not blockchain acceptance."""
from pathlib import Path
import os
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/ci/independent_gates_v1.sh'


class IndependentGatesTests(unittest.TestCase):
    def run_shell(self, body: str, seconds: str = '3') -> subprocess.CompletedProcess:
        return subprocess.run(
            ['bash', '-c', 'set -euo pipefail\nsource '+shlex.quote(str(HELPER))+'\n'+body],
            text=True, capture_output=True, timeout=12,
            env={**os.environ, 'TRNM_GATE_TIMEOUT_SECONDS': seconds},
        )

    def test_successful_commands(self):
        result = self.run_shell('trnm_gate true\ntrnm_gate printf "%s\\n" done\ntrnm_gate_finish')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('gate_commands=2 gate_failures=0', result.stdout)

    def test_first_failure_does_not_suppress_later_command(self):
        result = self.run_shell('trnm_gate bash -c "exit 7"\ntrnm_gate printf "%s\\n" second-ran\ntrnm_gate_finish')
        self.assertEqual(result.returncode, 1)
        self.assertIn('gate_command=1 exit=7', result.stdout)
        self.assertIn('\nsecond-ran\n', result.stdout)
        self.assertIn('gate_commands=2 gate_failures=1', result.stdout)

    def test_all_failures_count(self):
        result = self.run_shell('trnm_gate false\ntrnm_gate bash -c "exit 9"\ntrnm_gate_finish')
        self.assertEqual(result.returncode, 1)
        self.assertIn('gate_failures=2', result.stdout)

    def test_no_commands_fails(self):
        self.assertEqual(self.run_shell('trnm_gate_finish').returncode, 2)

    def test_missing_tool_is_failure(self):
        result = self.run_shell('trnm_gate /nonexistent/trnm-test-tool\ntrnm_gate true\ntrnm_gate_finish')
        self.assertEqual(result.returncode, 1)
        self.assertIn('gate_command=1 exit=127', result.stdout)
        self.assertIn('gate_commands=2', result.stdout)

    def test_timeout_is_failure_and_next_command_runs(self):
        result = self.run_shell('trnm_gate sleep 30\ntrnm_gate printf "%s\\n" after-timeout\ntrnm_gate_finish', '1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('exit=124', result.stdout)
        self.assertIn('\nafter-timeout\n', result.stdout)

    def test_invalid_timeout_is_not_silent_skip(self):
        for seconds in ('0', '-1', '1;true', '', '999999999999'):
            with self.subTest(seconds=seconds):
                # Empty selects the documented default; test empty command instead.
                body = 'trnm_gate\ntrnm_gate_finish' if not seconds else 'trnm_gate true\ntrnm_gate_finish'
                result = self.run_shell(body, seconds)
                self.assertEqual(result.returncode, 1)
                self.assertIn('exit=2', result.stdout)

    def test_arguments_are_not_eval(self):
        result = self.run_shell("trnm_gate printf '%s\\n' '$(printf injected); a b'\ntrnm_gate_finish")
        self.assertEqual(result.returncode, 0)
        self.assertIn('\n$(printf injected); a b\n', result.stdout)


class WorkflowWiringTests(unittest.TestCase):
    def protocol_job(self):
        text = (ROOT / '.github/workflows/trnm-required-baseline.yml').read_text()
        return text.split('  protocol-contract:\n', 1)[1].split('  fuzz-smoke:\n', 1)[0]

    def test_source_and_toolchain_prerequisites_are_explicit(self):
        job = self.protocol_job()
        condition = "if: ${{ !cancelled() && steps.protocol_source.outcome == 'success' && steps.protocol_host_tools.outcome == 'success' && steps.protocol_rust.outcome == 'success' && steps.protocol_node.outcome == 'success' }}"
        self.assertEqual(job.count(condition), 3)
        for identity in ('protocol_source', 'protocol_host_tools', 'protocol_rust', 'protocol_node'):
            self.assertEqual(job.count('id: '+identity+'\n'), 1)

    def test_every_independent_family_aggregates_failure(self):
        job = self.protocol_job()
        self.assertEqual(job.count('source scripts/ci/independent_gates_v1.sh'), 3)
        self.assertEqual(job.count('          trnm_gate_finish\n'), 3)
        self.assertNotIn('continue-on-error:', job)
        self.assertNotIn('|| true', job)

    def test_unchanged_required_job_names(self):
        import re
        text = (ROOT / '.github/workflows/trnm-required-baseline.yml').read_text()
        self.assertEqual(re.findall(r'^  ([a-z-]+):$', text.split('jobs:', 1)[1], re.M),
                         ['repository-truth', 'protocol-contract', 'fuzz-smoke',
                          'external-evidence-contract', 'rust-baseline'])

    def test_no_protocol_command_removed(self):
        job = self.protocol_job()
        self.assertEqual(sum(line.strip().startswith('trnm_gate ') for line in job.splitlines()), 29)
        self.assertIn('trnm_gate bash ./scripts/ci/check_canonical_development_plan.sh', job)
        self.assertIn('trnm_gate bash ./scripts/ci/check_poco_bft_v0_authenticated_checkpoint_handoff.sh', job)


if __name__ == '__main__':
    unittest.main(verbosity=2)
