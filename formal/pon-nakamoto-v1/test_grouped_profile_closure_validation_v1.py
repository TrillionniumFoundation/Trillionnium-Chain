"""Controls for validation scope and source identity, without fake native passes.

Temporary Git repositories exercise the real tracked-byte source guard. The CLI
failure case deliberately fails that source gate and must retain every planned
command as NOT_STARTED; no compiler or native execution is simulated as success.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / 'formal/pon-nakamoto-v1/experiments/validate_grouped_profile_closure_v1.py'


def load(path):
    spec = importlib.util.spec_from_file_location('closure_validation_control', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


D = load(DRIVER)
APPENDED_LABELS = [
    'native-task-core-all-targets', 'native-funded-service-contract', 'native-active-anchor',
    'native-demand-evidence', 'native-task-operation-v2', 'native-no-gain-fees',
    'demand-evidence-python', 'upgrade-policy-python', 'pq-research-integration-controls',
]


class CommandInventoryTests(unittest.TestCase):
    def test_frozen_original_driver_is_unchanged(self):
        expected = 'f32c38ce97270511783051b48b1249c7ce0e93af0c4e728077cdddfaeef64b64'
        self.assertEqual(D.ORIGINAL_DRIVER_SHA256, expected)
        self.assertEqual(D.ORIGINAL_LOADED_SHA256, expected)
        self.assertEqual(hashlib.sha256(Path(D.original.__file__).read_bytes()).hexdigest(), expected)

    def test_all_original_command_records_remain_an_exact_prefix(self):
        for env, fuzz in [({}, None), ({'TRNM_PQ_OPENSSL': '/pinned/provider/openssl'}, Path('/pinned/fuzz'))]:
            with self.subTest(env=env, fuzz=fuzz):
                original = D.original.commands('/pinned/python', env, fuzz)
                combined = D.commands('/pinned/python', env, fuzz)
                self.assertEqual(len(original), 24)
                self.assertEqual(len(combined), 33)
                self.assertEqual(combined[:24], original)
                self.assertEqual(D.original.canonical(combined[:24]), D.original.canonical(original))
                self.assertEqual([row['ordinal'] for row in combined], list(range(1, 34)))
                self.assertEqual([row['label'] for row in combined[24:]], APPENDED_LABELS)

    def test_each_command_hash_includes_the_original_flags_and_timeout(self):
        planned = D.commands(sys.executable, {}, None)
        for row in planned:
            with self.subTest(label=row['label']):
                body = {key: value for key, value in row.items() if key != 'command_sha256'}
                self.assertEqual(row['command_sha256'], hashlib.sha256(D.original.canonical(body)).hexdigest())
                self.assertEqual(row['timeout_seconds'], 1800)
        self.assertTrue(all('profile_closure_gate' not in row for row in planned[:24]))
        self.assertTrue(all(row['profile_closure_gate'] for row in planned[24:]))

    def test_core_gate_retains_all_three_crates_and_full_target_flags(self):
        core = D.commands(sys.executable, {}, None)[24]['command']
        packages = [core[index + 1] for index, value in enumerate(core) if value == '-p']
        self.assertEqual(packages, ['trnm-service-settlement', 'trnm-protocol', 'trnm-mvcc-fee'])
        for flag in ['--offline', '--locked', '--all-targets', '--all-features', '--no-fail-fast']:
            self.assertIn(flag, core)

    def test_added_native_targets_and_capture_are_explicit(self):
        planned = D.commands(sys.executable, {}, None)
        targets = [row['command'][row['command'].index('--test') + 1] for row in planned[25:30]]
        self.assertEqual(targets, ['funded_service_contract', 'native_active_anchor',
                                  'native_demand_evidence', 'native_task_operation_v2', 'no_gain_fees'])
        for row in planned[24:]:
            if row['label'] == 'native-task-operation-v2':
                self.assertEqual(row['environment_overrides'], {'TRNM_CAPTURE_NATIVE_TASK_CURRENT_V3': '1'})
                self.assertEqual(row['command'][-2:], ['--', '--nocapture'])
            else:
                self.assertEqual(row['environment_overrides'], {})

    def test_added_python_gates_name_exact_files_without_empty_discovery(self):
        planned = D.commands('/pinned/python', {}, None)
        self.assertEqual(planned[30]['command'], ['/pinned/python', '-B',
            'formal/pon-nakamoto-v1/test_demand_evidence.py', '-v'])
        self.assertEqual(planned[31]['command'], ['/pinned/python', '-B',
            'formal/pon-nakamoto-v1/test_upgrade_policy.py', '-v'])
        self.assertEqual(planned[32]['command'], ['/pinned/python', '-B',
            'scripts/ci/test_pq_research_integration.py'])
        self.assertTrue((ROOT / planned[32]['command'][2]).is_file())

    def test_missing_pq_executable_remains_an_original_launch_failure(self):
        planned = D.commands(sys.executable, {}, None)
        self.assertEqual(planned[3]['label'], 'openssl-version')
        self.assertEqual(planned[3]['command'], [None, 'version'])
        self.assertEqual(planned[3], D.original.commands(sys.executable, {}, None)[3])


PROBE = r'''
import importlib.util,json,pathlib,sys
path=pathlib.Path(sys.argv[1]); repo=pathlib.Path(sys.argv[2]); head=sys.argv[3]; mode=sys.argv[4]
spec=importlib.util.spec_from_file_location("closure_source_probe",path)
module=importlib.util.module_from_spec(spec)
exec(compile(path.read_bytes(),str(path),"exec"),module.__dict__)
if mode=="self_after_load":
    path.write_bytes(path.read_bytes()+b"\n# controlled source change after loading\n")
elif mode=="original_after_load":
    original=repo/module.ORIGINAL_RELATIVE
    original.write_bytes(original.read_bytes()+b"\n# controlled helper change after loading\n")
try:
    value=module.source_snapshot(repo,head)
except Exception as error:
    print(json.dumps({"type":type(error).__name__,"error":str(error)}))
    raise SystemExit(2)
print(json.dumps(value))
'''


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='grouped-profile-validator-control-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
                        PYTHONDONTWRITEBYTECODE='1')
        for relative in (D.RELATIVE, D.ORIGINAL_RELATIVE, 'scripts/ci/verify_ci_source.py'):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        (self.repo / 'tracked-material.txt').write_text('controlled material\n')
        self.git('init', '--quiet', '--object-format=sha1', '--template=')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=self.repo,
                                       env=self.env, stderr=subprocess.PIPE).decode().strip()

    def commit(self):
        self.git('add', '--all')
        self.git('-c', 'user.name=Validation control', '-c', 'user.email=control@example.invalid',
                 'commit', '--quiet', '-m', 'Controlled exact-source validation fixture')
        self.head = self.git('rev-parse', 'HEAD')

    def probe(self, mode='unchanged', repo=None, head=None):
        result = subprocess.run([sys.executable, '-B', '-c', PROBE,
            str(self.repo / D.RELATIVE), str(repo or self.repo), head or self.head, mode],
            env=self.env, capture_output=True, text=True, check=False)
        return result.returncode, json.loads(result.stdout)

    def cli(self, out, source_sha='not-a-source-commit'):
        return subprocess.run([sys.executable, '-B', str(self.repo / D.RELATIVE),
            '--repo', str(self.repo), '--source-sha', source_sha, '--out', str(out),
            '--runner', str(self.base / 'unbuilt-grouped'),
            '--fresh-runner', str(self.base / 'unbuilt-fresh'),
            '--authority-runner', str(self.base / 'unbuilt-authority')],
            cwd=self.base, env=self.env, capture_output=True, text=True, check=False)

    def test_exact_driver_pair_runs_the_original_complete_source_guard(self):
        code, value = self.probe()
        self.assertEqual(code, 0, value)
        self.assertEqual(value['tested_commit'], self.head)
        self.assertEqual(value['tracked_entries'], 4)
        self.assertTrue(value['tracked_worktree_verified'])
        self.assertFalse(value['tests_executed_by_identity_check'])

    def test_own_executing_path_cannot_borrow_another_repository(self):
        code, value = self.probe(repo=self.base)
        self.assertEqual(code, 2)
        self.assertEqual(value['error'], 'EXECUTING_DRIVER_OUTSIDE_EXPECTED_REPOSITORY')

    def test_own_driver_change_after_loading_is_rejected(self):
        code, value = self.probe(mode='self_after_load')
        self.assertEqual(code, 2)
        self.assertEqual(value['error'], 'EXECUTING_DRIVER_CHANGED_SINCE_LOAD')

    def test_own_driver_must_equal_its_expected_commit(self):
        path = self.repo / D.RELATIVE
        path.write_bytes(path.read_bytes() + b'\n# controlled uncommitted driver bytes\n')
        code, value = self.probe()
        self.assertEqual(code, 2)
        self.assertEqual(value['error'], 'EXECUTING_DRIVER_NOT_EXACT_COMMITTED_BYTES:' + D.RELATIVE)

    def test_original_helper_change_after_loading_is_rejected(self):
        code, value = self.probe(mode='original_after_load')
        self.assertEqual(code, 2)
        self.assertEqual(value['error'], 'ORIGINAL_DRIVER_NOT_EXACT_FROZEN_BYTES')

    def test_even_committed_original_helper_changes_cannot_silently_replace_the_prefix(self):
        path = self.repo / D.ORIGINAL_RELATIVE
        path.write_bytes(path.read_bytes() + b'\n# controlled changed prior driver\n')
        self.commit()
        code, value = self.probe()
        self.assertEqual(code, 2)
        self.assertEqual(value['error'], 'ORIGINAL_DRIVER_NOT_EXACT_FROZEN_BYTES')

    def test_other_tracked_bytes_are_checked_by_the_reused_source_guard(self):
        (self.repo / 'tracked-material.txt').write_text('changed material\n')
        code, value = self.probe()
        self.assertEqual(code, 2)
        self.assertIn('source is not clean', value['error'])

    def test_failed_source_gate_retains_all_thirty_three_unstarted_commands(self):
        out = self.base / 'validation'
        result = self.cli(out)
        self.assertEqual(result.returncode, 1, result.stderr)
        plan = json.loads((out / 'plan.json').read_text())
        rows = json.loads((out / 'commands.json').read_text())
        ledger = [json.loads(line) for line in (out / 'commands.ndjson').read_text().splitlines()]
        summary = json.loads((out / 'summary.json').read_text())
        self.assertEqual(plan['schema'], 'pon-grouped-profile-closure-validation-plan-v1')
        self.assertEqual(summary['schema'], 'pon-grouped-profile-closure-local-validation-v1')
        self.assertEqual(len(rows), 33)
        self.assertEqual(rows, ledger)
        self.assertTrue(all(row['status'] == 'NOT_STARTED' and not row['process_started'] for row in rows))
        self.assertTrue(all(row['reason'] == 'EXACT_SOURCE_GATE_FAILED' for row in rows))
        self.assertEqual([row['label'] for row in rows], [row['label'] for row in plan['commands']])
        self.assertEqual(summary['status'], 'FAIL')
        self.assertEqual(summary['commands_passed'], 0)
        self.assertEqual(summary['commands_not_started'], 33)
        self.assertEqual(summary['commands_timed_out'], 0)
        self.assertTrue(summary['complete_command_denominator'])
        self.assertEqual(summary['runner_bindings']['status'], 'FAIL')
        self.assertEqual(len(summary['source_failures']), 2)
        self.assertEqual(len(list(out.glob('*.result.json'))), 33)
        for key in ('full_node_target_inventory_executed', 'full_workspace_unit_tests_executed',
                    'original_service_campaign_executed', 'prior_failed_campaigns_superseded',
                    'genuine_independent_demand_established', 'physical_resource_lower_bound_proved',
                    'native_consensus_profile_qualified', 'pow_qualified', 'production_activation'):
            self.assertFalse(summary[key])
        self.assertEqual(summary['chainwork_awarded'], 0)

    def test_output_directory_is_create_only(self):
        out = self.base / 'validation'
        self.assertEqual(self.cli(out).returncode, 1)
        retained = {path.name: path.read_bytes() for path in out.iterdir()}
        repeat = self.cli(out)
        self.assertNotEqual(repeat.returncode, 0)
        self.assertIn('FileExistsError', repeat.stderr)
        self.assertEqual({path.name: path.read_bytes() for path in out.iterdir()}, retained)

    def test_output_cannot_be_created_inside_the_source_checkout(self):
        out = self.repo / 'forbidden-output'
        result = self.cli(out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('OUTPUT_MUST_BE_OUTSIDE_SOURCE_CHECKOUT', result.stderr)
        self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
