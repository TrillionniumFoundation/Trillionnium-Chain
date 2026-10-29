#!/usr/bin/env python3
"""Real subprocess interruption controls; fake sudo only checks cleanup dispatch.

No test here grants cgroup/root-lease authority or represents a native campaign.
The unchanged history_fixed_parent_v2 root manager owns that separate boundary.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('pair', HERE / 'run_history_profile_pair_diagnostic_v1.py')
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('actual subprocess condition did not complete')


def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rpartition(') ')[2].split()[0] != 'Z'
    except FileNotFoundError:
        return False


class PairControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='history-pair-controls-')
        self.base = Path(self.temporary.name)
        self.source = self.base / 'source'
        path = self.source / pair.WORKFLOW
        path.parent.mkdir(parents=True)
        path.write_bytes((ROOT / pair.WORKFLOW).read_bytes())

    def tearDown(self):
        self.temporary.cleanup()

    def fake_environment(self, fail_probe=False):
        # This executable never invokes sudo or systemctl. It records the
        # original command arguments, then models only the dispatch exit code.
        executable = self.base / 'bin' / 'sudo'
        executable.parent.mkdir(exist_ok=True)
        executable.write_text(
            '#!' + sys.executable + '\n'
            'import json,os,sys\n'
            'with open(os.environ["DISPATCH_RECORD"], "a") as f:\n'
            ' f.write(json.dumps(sys.argv[1:])+"\\n")\n'
            'failed=os.environ.get("FAIL_PROBE")=="1" and "cleanup-probe" in sys.argv\n'
            'print(json.dumps({"dispatch_only":True,"complete_success":not failed}))\n'
            'sys.exit(7 if failed else 0)\n')
        executable.chmod(0o755)
        return dict(os.environ, PATH=str(executable.parent) + ':' + os.environ['PATH'],
                    GITHUB_RUN_ID='1234567', GITHUB_RUN_ATTEMPT='9',
                    DISPATCH_RECORD=str(self.base / 'dispatch.jsonl'),
                    FAIL_PROBE='1' if fail_probe else '0')

    def test_exact_original_steps_and_step_budget_are_retained(self):
        steps = pair.extract_original_steps(self.source / pair.WORKFLOW)
        self.assertEqual(len(steps), 12)
        self.assertEqual([s['timeout_seconds'] for s in steps if s['timeout_seconds']], [720])
        for index, step in enumerate(steps):
            script = self.base / f'original-{index}.sh'
            script.write_text(step['code'])
            self.assertEqual(subprocess.run(['/usr/bin/bash', '-n', str(script)]).returncode, 0)
        self.assertIn('cleanup-probe', next(s['code'] for s in steps if s['name'] == pair.CLEANUP_NAME))

    def test_timeout_kills_term_ignoring_grandchild_and_preserves_sibling(self):
        grandchild = self.base / 'grandchild.py'
        pidfile = self.base / 'grandchild.pid'
        grandchild.write_text(
            'import os,signal,time\nfrom pathlib import Path\n'
            'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
            f'Path({str(pidfile)!r}).write_text(str(os.getpid()))\n'
            'while True: time.sleep(1)\n')
        leader = self.base / 'leader.py'
        leader.write_text(
            'import subprocess,sys,time\n'
            f'subprocess.Popen([sys.executable,{str(grandchild)!r}])\n'
            'while True: time.sleep(1)\n')
        script = self.base / 'work.sh'
        script.write_text(f'exec {sys.executable} {leader}\n')
        sibling = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                   start_new_session=True)
        try:
            result = pair.invoke(script, self.base / 'timeout.log', self.source, os.environ,
                                 time.monotonic() + 0.4, grace_seconds=0.1)
            self.assertTrue(result['timed_out'])
            self.assertTrue(pidfile.exists())
            until(lambda: not alive(int(pidfile.read_text())))
            self.assertIsNone(sibling.poll())
        finally:
            sibling.kill()
            sibling.wait()

    def test_reaped_child_pid_is_never_signalled(self):
        child = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True)
        self.assertEqual(child.wait(), 0)
        with mock.patch.object(pair.os, 'killpg') as kill:
            self.assertEqual(pair.stop_owned_group(child, 0), 0)
            kill.assert_not_called()

    def test_signal_at_popen_publication_does_not_lose_child_handle(self):
        script = self.base / 'spawn-race.sh'
        script.write_text(f'exec {sys.executable} -c "import time; time.sleep(30)"\n')
        popen = subprocess.Popen
        children = []
        previous = signal.signal(signal.SIGTERM, pair.interrupt)
        def at_publication(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            os.kill(os.getpid(), signal.SIGTERM)
            return child
        try:
            with mock.patch.object(pair.subprocess, 'Popen', side_effect=at_publication):
                result = pair.invoke(script, self.base / 'spawn-race.log', self.source, os.environ,
                                     time.monotonic() + 5, grace_seconds=0.1)
            self.assertEqual(result['interrupted_signal'], signal.SIGTERM)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
            self.assertNotEqual(children[0].returncode, 0)
        finally:
            pair.INTERRUPTED_SIGNAL = None
            signal.signal(signal.SIGTERM, previous)
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_sigterm_records_interruption_and_stops_live_step(self):
        worker = self.base / 'work.sh'
        worker.write_text(f'exec {sys.executable} -c "import time; time.sleep(30)"\n')
        driver = self.base / 'driver.py'
        driver.write_text(
            f'import sys; sys.path.insert(0,{str(HERE)!r})\n'
            'import json,os,signal,time\nfrom pathlib import Path\n'
            'import run_history_profile_pair_diagnostic_v1 as p\n'
            'signal.signal(signal.SIGTERM,p.interrupt)\n'
            f'Path({str(self.base / "ready")!r}).touch()\n'
            f'r=p.invoke(Path({str(worker)!r}),Path({str(self.base / "signal.log")!r}),'
            f'Path({str(self.source)!r}),os.environ,time.monotonic()+20,grace_seconds=0.1)\n'
            f'Path({str(self.base / "signal-result.json")!r}).write_text(json.dumps(r))\n')
        child = subprocess.Popen([sys.executable, str(driver)], start_new_session=True)
        try:
            until(lambda: (self.base / 'signal.log').exists())
            child.send_signal(signal.SIGTERM)
            self.assertEqual(child.wait(timeout=5), 0)
            result = json.loads((self.base / 'signal-result.json').read_text())
            self.assertEqual(result['interrupted_signal'], signal.SIGTERM)
            self.assertFalse(result['timed_out'])
            self.assertNotEqual(result['returncode'], 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_fresh_cleanup_after_hard_controller_death_and_corrupt_results(self):
        env = self.fake_environment()
        output = self.base / 'pair'
        output.mkdir()
        original = b'{interrupted and deliberately unparseable'
        (output / 'pair-results.json').write_bytes(original)
        # The independent cleanup must work without a live controller and
        # without trusting/reconstructing any failed controller JSON receipt.
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        child.kill()
        self.assertEqual(child.wait(), -signal.SIGKILL)
        result = pair.cleanup_only(self.source, output, env)
        self.assertTrue(result['complete_success'])
        self.assertEqual((output / 'pair-results.json').read_bytes(), original)
        calls = [json.loads(row) for row in (self.base / 'dispatch.jsonl').read_text().splitlines()]
        self.assertEqual(len(calls), 2)
        self.assertEqual([row[4] for row in calls], ['cleanup-probe', 'cleanup'])
        self.assertTrue(all(row[-2:] == ['--owner', '1234567.9'] for row in calls))

    def test_cleanup_failure_is_retained_and_both_original_actions_run(self):
        env = self.fake_environment(fail_probe=True)
        output = self.base / 'failed'
        result = pair.cleanup_only(self.source, output, env)
        self.assertFalse(result['complete_success'])
        self.assertEqual(len((self.base / 'dispatch.jsonl').read_text().splitlines()), 2)
        attempts = list(output.glob('owned-cleanup-*/cleanup-results.json'))
        self.assertEqual(len(attempts), 1)
        self.assertEqual(json.loads(attempts[0].read_text()), result)
        env['FAIL_PROBE'] = '0'
        self.assertTrue(pair.cleanup_only(self.source, output, env)['complete_success'])
        self.assertEqual(len(list(output.glob('owned-cleanup-*/cleanup-results.json'))), 2)
        self.assertFalse(json.loads(attempts[0].read_text())['complete_success'])

    def test_failed_final_source_read_still_retains_partial_artifact_inventory(self):
        executable = self.base / 'bin' / 'python3'
        executable.parent.mkdir()
        executable.write_text(
            '#!' + sys.executable + '\n'
            'import os,sys\n'
            'if len(sys.argv)>1 and sys.argv[1]=="scripts/ci/verify_ci_source.py":\n'
            ' print("retained actual failing source verifier dispatch")\n'
            ' sys.exit(7)\n'
            'os.execv(sys.executable,[sys.executable,*sys.argv[1:]])\n')
        executable.chmod(0o755)
        output = self.base / 'partial'
        output.mkdir()
        (output / 'failed-native.log').write_text('original failed native observation\n')
        step = next(s for s in pair.extract_original_steps(self.source / pair.WORKFLOW)
                    if s['name'] == 'Preserve final source verification and all partial artifact hashes')
        script = self.base / 'preserve.sh'
        script.write_text(step['code'])
        env = dict(os.environ, PATH=str(executable.parent) + ':' + os.environ['PATH'],
                   OUT=str(output), EXPECTED_HEAD='a' * 40)
        result = pair.invoke(script, self.base / 'preserve.log', self.source, env,
                             time.monotonic() + 5)
        self.assertNotEqual(result['returncode'], 0)
        inventory = json.loads((output / 'artifact-files.json').read_text())
        files = {row['path']: row for row in inventory['files']}
        self.assertEqual(files['failed-native.log']['sha256'], pair.digest(output / 'failed-native.log'))
        self.assertIn('source-after.log', files)

    def test_changed_source_and_wrong_owner_never_dispatch_cleanup(self):
        env = self.fake_environment()
        for wrong in ('', '0', '1;exit', '../123', '1.2', '1\n2'):
            with self.assertRaises(ValueError):
                pair.cleanup_only(self.source, self.base / 'bad-owner', dict(env, GITHUB_RUN_ID=wrong))
        self.assertFalse((self.base / 'bad-owner').exists())
        workflow = self.source / pair.WORKFLOW
        workflow.write_bytes(workflow.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'workflow bytes changed'):
            pair.cleanup_only(self.source, self.base / 'bad-source', env)
        self.assertFalse((self.base / 'dispatch.jsonl').exists())

    def test_expired_deadline_executes_no_step(self):
        script = self.base / 'not-run.sh'
        marker = self.base / 'must-not-exist'
        script.write_text(f'touch {marker}\n')
        result = pair.invoke(script, self.base / 'not-run.log', self.source, os.environ,
                             time.monotonic() - 1)
        self.assertFalse(result['executed'])
        self.assertTrue(result['timed_out'])
        self.assertFalse(marker.exists())

    def test_first_arm_readback_failure_does_not_skip_second_but_cleanup_failure_does(self):
        for cleanup_exit, expected_arms in ((0, 2), (7, 1)):
            output = self.base / ('arm-failure-' + str(cleanup_exit))
            step = {'name': pair.CLEANUP_NAME, 'always': True,
                    'timeout_seconds': None, 'code': f'exit {cleanup_exit}\n'}
            env = dict(os.environ, EXPECTED_HEAD='a' * 40,
                       GITHUB_RUN_ID='1234567', GITHUB_RUN_ATTEMPT='9')
            args = SimpleNamespace(root=self.source, output=output, order='strict-then-n8')
            with mock.patch.object(pair, 'extract_original_steps', return_value=[step]), \
                    mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(pair.run(args), 1)
            result = json.loads((output / 'pair-results.json').read_text())
            self.assertEqual(len(result['arms']), expected_arms)
            self.assertFalse(result['pair_binding_valid'])
            self.assertFalse(result['all_original_campaigns_passed'])
            if cleanup_exit == 0:
                self.assertTrue(all('readback_failure' in arm for arm in result['arms']))

    def successful_record_fixture_steps(self, final_status=0, signal_during_final_cleanup=False):
        # These are expressly synthetic reader inputs around actual /usr/bin/true
        # ELF bytes. They test orchestration of existing success records, never
        # assert that the fixture executed or qualified a native campaign.
        fixture = '''import hashlib,json,os
from pathlib import Path
out=Path(os.environ['OUT'])
source={'tested_commit':os.environ['EXPECTED_HEAD'],'tracked_worktree_verified':True}
for name in ('source-before.json','source-after.json'):
    (out/name).write_text(json.dumps(source))
binary=Path('/usr/bin/true').read_bytes()
(out/'fixture-elf.bin').write_bytes(binary)
digest=hashlib.sha256(binary).hexdigest()
campaign={'binary':{'retained':'fixture-elf.bin','bytes':len(binary),
    'sha256_before':digest,'sha256_after':digest},
    'attempts':[{'actual_verifier_boundary_readback':True,'report_validation_failure':None,
        'step':{'error':None,'outer_stage_timeout_seconds':600},'original_criteria_met':True}
        for _ in range(3)],
    'original_inputs':{'fixture_only':True},'expected_resources':{'fixture_only':True},
    'separate_verifier_limits':{'fixture_only':True},
    'history_resource_profile':os.environ['HISTORY_RESOURCE_PROFILE'],'complete_success':True}
(out/'results.json').write_text(json.dumps(campaign))
(out/'verifier-lifeline').mkdir()
(out/'verifier-lifeline/results.json').write_text(json.dumps({'complete_success':True}))
'''
        cleanup = 'exit 0\n'
        if signal_during_final_cleanup:
            cleanup = '''case "$OUT" in
  */owned-cleanup-*) kill -TERM "$PAIR_TEST_CONTROLLER_PID"; sleep 0.05 ;;
esac
exit 0
'''
        return [
            {'name': 'Synthetic already-successful arm records', 'always': False,
             'timeout_seconds': None, 'code': f'{sys.executable} - <<\'PY\'\n{fixture}PY\n'},
            {'name': pair.CLEANUP_NAME, 'always': True, 'timeout_seconds': None, 'code': cleanup},
            {'name': 'Preserve final source verification and all partial artifact hashes',
             'always': True, 'timeout_seconds': None, 'code': f'exit {final_status}\n'},
        ]

    def test_existing_successful_arm_records_cannot_hide_failed_final_step(self):
        env = dict(os.environ, EXPECTED_HEAD='a' * 40,
                   GITHUB_RUN_ID='1234567', GITHUB_RUN_ATTEMPT='9')
        output = self.base / 'failed-final-step'
        args = SimpleNamespace(root=self.source, output=output, order='strict-then-n8')
        steps = self.successful_record_fixture_steps(final_status=7)
        with mock.patch.object(pair, 'extract_original_steps', return_value=steps), \
                mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(pair.run(args), 1)
        result = json.loads((output / 'pair-results.json').read_text())
        self.assertTrue(result['all_original_campaigns_passed'])
        self.assertTrue(result['both_independent_lifelines_passed'])
        self.assertTrue(result['safety_cleanup']['complete_success'])
        self.assertTrue(all(arm['complete'] for arm in result['arms']))
        self.assertEqual([[step['returncode'] for step in arm['steps']] for arm in result['arms']],
                         [[0, 0, 7], [0, 0, 7]])
        self.assertFalse(result['all_required_steps_passed'])
        self.assertFalse(result['pair_binding_valid'])
        self.assertIsNotNone(result['failure'])

    def test_signal_during_final_safety_cleanup_is_retained_without_aborting_cleanup(self):
        env = dict(os.environ, EXPECTED_HEAD='a' * 40,
                   GITHUB_RUN_ID='1234567', GITHUB_RUN_ATTEMPT='9',
                   PAIR_TEST_CONTROLLER_PID=str(os.getpid()))
        output = self.base / 'final-cleanup-signal'
        args = SimpleNamespace(root=self.source, output=output, order='strict-then-n8')
        steps = self.successful_record_fixture_steps(signal_during_final_cleanup=True)
        previous = signal.signal(signal.SIGTERM, pair.interrupt)
        try:
            with mock.patch.object(pair, 'extract_original_steps', return_value=steps), \
                    mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(pair.run(args), 1)
            result = json.loads((output / 'pair-results.json').read_text())
            self.assertTrue(result['all_original_campaigns_passed'])
            self.assertTrue(result['all_required_steps_passed'])
            self.assertTrue(result['safety_cleanup']['complete_success'])
            self.assertEqual(result['controller_interrupted_signal'], signal.SIGTERM)
            self.assertIsNotNone(result['failure'])
        finally:
            pair.INTERRUPTED_SIGNAL = None
            signal.signal(signal.SIGTERM, previous)

    def test_all_required_steps_can_finish_successfully_without_interruption(self):
        env = dict(os.environ, EXPECTED_HEAD='a' * 40,
                   GITHUB_RUN_ID='1234567', GITHUB_RUN_ATTEMPT='9')
        output = self.base / 'all-steps-complete'
        args = SimpleNamespace(root=self.source, output=output, order='strict-then-n8')
        with mock.patch.object(pair, 'extract_original_steps',
                               return_value=self.successful_record_fixture_steps()), \
                mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(pair.run(args), 0)
        result = json.loads((output / 'pair-results.json').read_text())
        self.assertTrue(result['pair_binding_valid'])
        self.assertTrue(result['all_required_steps_passed'])
        self.assertTrue(result['all_original_campaigns_passed'])
        self.assertTrue(result['both_independent_lifelines_passed'])
        self.assertTrue(result['safety_cleanup']['complete_success'])
        self.assertIsNone(result['failure'])
        self.assertIsNone(result['controller_interrupted_signal'])

    def test_cli_does_not_allow_cleanup_to_select_a_native_profile(self):
        result = subprocess.run([sys.executable, str(HERE / 'run_history_profile_pair_diagnostic_v1.py'),
                                 '--root', str(self.source), '--output', str(self.base / 'cli'),
                                 '--cleanup-only', '--order', 'strict-then-n8'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.base / 'cli').exists())


if __name__ == '__main__':
    unittest.main()
