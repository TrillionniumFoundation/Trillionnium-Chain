#!/usr/bin/env python3
"""Real Git/filesystem negatives and an independent raw-byte-path regression."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from verify_ci_source import verify


class TrackedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='trnm-ci-raw-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q', '-b', 'candidate')
        self.git('config', 'user.name', 'Source integrity fixture')
        self.git('config', 'user.email', 'ci-test@example.invalid')
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'source.rs').write_bytes(b'const VALID: bool = true;\n')
        (self.root / 'empty').write_bytes(b'')
        (self.root / 'odd\tname\n.bin').write_bytes(b'\x00\xff\x01')
        (self.root / 'run.sh').write_text('#!/bin/sh\nexit 0\n')
        (self.root / 'run.sh').chmod(0o755)
        (self.root / 'link').symlink_to('nested/source.rs')
        self.git('add', '.')
        self.git('commit', '-qm', 'source fixture')
        self.head = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True,
                                       stderr=subprocess.DEVNULL).strip()

    def check(self):
        return verify('head', self.head, root=self.root)

    def test_valid_raw_files_modes_and_symlink(self):
        result = self.check()
        self.assertTrue(result['tracked_worktree_verified'])
        self.assertEqual(result['tracked_entries'], 5)
        self.assertEqual(result['tested_commit'], self.head)
        self.assertFalse(result['tests_executed_by_identity_check'])

    def test_assume_unchanged_cannot_hide_modified_source(self):
        self.git('update-index', '--assume-unchanged', 'nested/source.rs')
        (self.root / 'nested/source.rs').write_text('changed\n')
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaises(ValueError):
            self.check()

    def test_skip_worktree_cannot_hide_modified_source(self):
        self.git('update-index', '--skip-worktree', 'nested/source.rs')
        (self.root / 'nested/source.rs').write_text('changed\n')
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaises(ValueError):
            self.check()

    def test_hidden_index_flag_is_rejected_even_without_changes(self):
        self.git('update-index', '--assume-unchanged', 'empty')
        with self.assertRaises(ValueError):
            self.check()

    def test_same_size_stat_cached_change_is_rejected(self):
        self.git('config', 'core.trustctime', 'false')
        self.git('config', 'core.checkStat', 'minimal')
        self.git('update-index', '--refresh')
        source = self.root / 'nested/source.rs'
        info = source.stat()
        source.write_bytes(source.read_bytes().replace(b'true', b'TRUE'))
        os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaises(ValueError):
            self.check()

    def test_untracked_configuration_cannot_hide_new_source(self):
        self.git('config', 'status.showUntrackedFiles', 'no')
        (self.root / 'injected.py').write_text('print("not committed")\n')
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaises(ValueError):
            self.check()

    def test_executable_mode_checked_even_when_git_ignores_filemode(self):
        self.git('config', 'core.filemode', 'false')
        (self.root / 'run.sh').chmod(0o644)
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaises(ValueError):
            self.check()

    def test_regular_file_symlink_substitution_rejected(self):
        source = self.root / 'nested/source.rs'
        source.unlink()
        source.symlink_to('../empty')
        with self.assertRaises(ValueError):
            self.check()

    def test_tracked_symlink_target_change_rejected(self):
        link = self.root / 'link'
        link.unlink()
        link.symlink_to('empty')
        with self.assertRaises(ValueError):
            self.check()

    def test_intermediate_directory_symlink_rejected(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-other-tree-') as other:
            destination = Path(other) / 'nested'
            shutil.copytree(self.root / 'nested', destination)
            shutil.rmtree(self.root / 'nested')
            (self.root / 'nested').symlink_to(destination, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.check()

    def test_nonregular_file_rejected_without_waiting_for_fifo(self):
        source = self.root / 'nested/source.rs'
        source.unlink()
        os.mkfifo(source)
        with self.assertRaises(ValueError):
            self.check()

    def test_replacement_commit_cannot_relabel_different_source(self):
        (self.root / 'nested/source.rs').write_text('different commit\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'other source')
        replacement = self.git('rev-parse', 'HEAD')
        self.git('reset', '--hard', self.head)
        self.git('replace', self.head, replacement)
        self.git('read-tree', '--reset', '-u', 'HEAD')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.head)
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaises(ValueError):
            self.check()

    def test_graft_file_is_rejected(self):
        path = self.root / '.git/info/grafts'
        path.write_text(self.head + '\n')
        with self.assertRaises(ValueError):
            self.check()

    def test_staged_change_is_rejected(self):
        (self.root / 'empty').write_bytes(b'changed')
        self.git('add', '.')
        with self.assertRaises(ValueError):
            self.check()

    def test_subdirectory_is_not_a_complete_source_root(self):
        with self.assertRaises(ValueError):
            verify('head', self.head, root=self.root / 'nested')

    def test_receipt_reuses_raw_source_guard(self):
        import ci_observation
        with patch.object(ci_observation, 'ROOT', self.root):
            self.assertEqual(ci_observation.source()['source_state'], 'committed-clean')
            self.git('update-index', '--assume-unchanged', 'nested/source.rs')
            (self.root / 'nested/source.rs').write_text('uncommitted bytes\n')
            result = ci_observation.source()
        self.assertEqual(result['commit'], self.head)
        self.assertEqual(result['source_state'], 'dirty-candidate')
        self.assertFalse(result['tracked_worktree_verified'])
        self.assertIn('source_verification_error', result)

    def test_actual_bytes_are_checked_even_if_status_reports_clean(self):
        # The real cache-hiding cases above exercise Git itself. This case proves
        # the hash path is independently necessary, not just flag screening.
        original = subprocess.check_output
        def status_clean(command, *args, **kwargs):
            if 'status' in command:
                return b''
            return original(command, *args, **kwargs)
        source = self.root / 'nested/source.rs'
        source.write_bytes(source.read_bytes().replace(b'true', b'TRUE'))
        with patch('verify_ci_source.subprocess.check_output', side_effect=status_clean):
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                self.check()


    def _fenced_child(self, body, *, checked_call=False, timeout=5):
        import ci_observation
        import sys
        log = self.root / '.git' / 'fenced-command.log'
        marker = self.root / '.git' / 'entered'
        program = ('from pathlib import Path\nimport subprocess, sys, time\n'
                   'Path(sys.argv[1]).write_text("entered")\n'
                   'print("actual-child-output", flush=True)\n' + body)
        command = [sys.executable, '-S', '-c', program, str(marker)]
        observations = []
        with patch.object(ci_observation, 'ROOT', self.root):
            if checked_call:
                with self.assertRaisesRegex(RuntimeError, 'command exited 125'):
                    ci_observation.checked(command, log, observations, cwd=self.root,
                                           timeout=timeout, expected_source=self.head)
                result = observations[0]
            else:
                result = ci_observation.run(command, log, cwd=self.root,
                                            timeout=timeout, expected_source=self.head)
        return result, log, marker

    def _finish_report(self, report, directory='receipt'):
        import ci_observation
        import json
        output = self.root / '.git' / directory
        output.mkdir()
        (output / 'failure.log').write_text('original diagnostic\n')
        with patch.object(ci_observation, 'ROOT', self.root):
            ci_observation.finish(output, report, ['nested/source.rs'])
        return json.loads((output / 'manifest.json').read_text())

    def test_source_fence_clean_child_keeps_actual_success_and_bytes(self):
        result, log, marker = self._fenced_child('')
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['process_exit_code'], 0)
        self.assertTrue(marker.is_file())
        self.assertTrue(result['executed'])
        self.assertTrue(result['source_before_verified'])
        self.assertTrue(result['source_after_verified'])
        self.assertEqual(result['expected_source'], self.head)
        self.assertEqual(log.read_text(), 'actual-child-output\n')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.head)

    def test_source_fence_dirty_before_command_cannot_start_child(self):
        (self.root / 'nested/source.rs').write_text('uncommitted')
        result, log, marker = self._fenced_child('raise SystemExit(0)')
        self.assertEqual(result['exit_code'], 125)
        self.assertIsNone(result['process_exit_code'])
        self.assertFalse(result['executed'])
        self.assertFalse(result['source_before_verified'])
        self.assertFalse(result['source_after_verified'])
        self.assertEqual(result['source_failure_phase'], 'before')
        self.assertFalse(marker.exists())
        self.assertEqual(log.read_bytes(), b'')

    def test_source_fence_clean_wrong_head_cannot_start_child(self):
        (self.root / 'empty').write_text('other commit')
        self.git('add', '.'); self.git('commit', '-qm', 'other')
        self.assertEqual(self.git('status', '--porcelain'), '')
        result, _, marker = self._fenced_child('')
        self.assertEqual(result['exit_code'], 125)
        self.assertEqual(result['source_failure_phase'], 'before')
        self.assertFalse(marker.exists())

    def test_source_fence_zero_exit_with_real_dirty_source_is_not_success(self):
        result, log, marker = self._fenced_child(
            'Path("nested/source.rs").write_text("changed by actual child")\n')
        self.assertTrue(marker.is_file())
        self.assertEqual(result['process_exit_code'], 0)
        self.assertEqual(result['exit_code'], 125)
        self.assertTrue(result['source_before_verified'])
        self.assertFalse(result['source_after_verified'])
        self.assertEqual(result['source_failure_phase'], 'after')
        self.assertEqual(log.read_text(), 'actual-child-output\n')

    def test_source_fence_keeps_nonzero_primary_error_and_drift(self):
        result, log, _ = self._fenced_child(
            'Path("nested/source.rs").write_text("changed")\nraise SystemExit(7)\n')
        self.assertEqual(result['process_exit_code'], 7)
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual(result['source_failure_phase'], 'after')
        self.assertIn('actual-child-output', log.read_text())

    def test_source_fence_checked_retains_actual_failed_observation(self):
        result, _, marker = self._fenced_child(
            'Path("nested/source.rs").write_text("changed")\n', checked_call=True)
        self.assertTrue(marker.is_file())
        self.assertEqual(result['exit_code'], 125)
        self.assertEqual(result['process_exit_code'], 0)

    def test_source_fence_clean_commit_switch_during_command_is_rejected(self):
        result, _, _ = self._fenced_child(
            'Path("empty").write_text("new commit")\n'
            'subprocess.run(["git", "add", "."], check=True)\n'
            'subprocess.run(["git", "commit", "-qm", "new source"], check=True)\n')
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertNotEqual(self.git('rev-parse', 'HEAD'), self.head)
        self.assertEqual(result['process_exit_code'], 0)
        self.assertEqual(result['exit_code'], 125)
        self.assertEqual(result['expected_source'], self.head)

    def test_source_fence_index_hidden_child_mutation_still_refuses(self):
        result, _, _ = self._fenced_child(
            'subprocess.run(["git", "update-index", "--assume-unchanged", '
            '"nested/source.rs"], check=True)\n'
            'Path("nested/source.rs").write_text("hidden mutation")\n')
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertEqual(result['exit_code'], 125)
        self.assertFalse(result['source_verified'])

    def test_source_fence_timeout_and_source_failure_preserve_both(self):
        result, _, marker = self._fenced_child(
            'Path("nested/source.rs").write_text("before timeout")\ntime.sleep(30)\n',
            timeout=1)
        self.assertTrue(marker.is_file())
        self.assertEqual(result['exit_code'], 124)
        self.assertTrue(result['timed_out'])
        self.assertEqual(result['source_failure_phase'], 'after')
        self.assertIsNotNone(result['process_exit_code'])

    def test_source_fence_pin_is_clean_and_does_not_follow_later_changes(self):
        import ci_observation
        with patch.object(ci_observation, 'ROOT', self.root):
            pinned = ci_observation.pin_source()
            self.assertEqual(pinned, self.head)
            (self.root / 'empty').write_text('dirty')
            with self.assertRaisesRegex(ValueError, 'CI_SOURCE_NOT_COMMITTED_CLEAN'):
                ci_observation.pin_source()
        self.assertEqual(pinned, self.head)

    def test_source_fence_finish_dirty_source_cannot_write_pass(self):
        (self.root / 'nested/source.rs').write_text('different bytes')
        result = self._finish_report(dict(result='PASS', source_expected=self.head,
                                         acceptance_granted=False))
        self.assertEqual(result['result'], 'FAIL')
        self.assertFalse(result['source_consistent'])
        self.assertEqual(result['input_sha256'], {})
        self.assertIn('failure.log', result['artifact_sha256'])
        self.assertFalse(result['acceptance_granted'])

    def test_source_fence_finish_clean_other_commit_cannot_borrow_pass(self):
        (self.root / 'empty').write_text('new source')
        self.git('add', '.'); self.git('commit', '-qm', 'other')
        result = self._finish_report(dict(result='PASS', source_expected=self.head))
        self.assertEqual(result['source']['source_state'], 'committed-clean')
        self.assertEqual(result['result'], 'FAIL')
        self.assertFalse(result['source_consistent'])
        self.assertEqual(result['source_expected'], self.head)

    def test_source_fence_finish_requires_initial_pin(self):
        result = self._finish_report(dict(result='PASS'))
        self.assertEqual(result['result'], 'FAIL')
        self.assertFalse(result['source_consistent'])

    def test_source_fence_finish_valid_source_never_upgrades_existing_failure(self):
        for status in ('PASS', 'FAIL'):
            result = self._finish_report(dict(result=status, source_expected=self.head,
                                             error='original failure', acceptance_granted=False),
                                         'receipt-' + status)
            self.assertEqual(result['result'], status)
            self.assertEqual(result['error'], 'original failure')
            self.assertTrue(result['source_consistent'])
            self.assertIn('nested/source.rs', result['input_sha256'])
            self.assertFalse(result['acceptance_granted'])

    def test_source_fence_dirty_source_preserves_primary_failure(self):
        (self.root / 'empty').write_text('changed')
        result = self._finish_report(dict(result='FAIL', source_expected=self.head,
                                         error='dependency policy refused'))
        self.assertEqual(result['error'], 'dependency policy refused')
        self.assertEqual(result['result'], 'FAIL')
        self.assertIn('source_error', result)

    def test_source_fence_existing_fuzz_and_supply_callers_pin_every_command(self):
        # Wiring inventory only; this does not claim libFuzzer/cargo-deny ran.
        import ast
        root = Path(__file__).resolve().parents[2]
        for filename in ('run_fuzz_smoke.py', 'run_supply_chain.py'):
            tree = ast.parse((root / 'scripts/ci' / filename).read_text())
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id in ('run', 'checked')]
            self.assertGreaterEqual(len(calls), 4)
            for call in calls:
                source_args = [arg.value for arg in call.keywords if arg.arg == 'expected_source']
                self.assertEqual(len(source_args), 1)
                self.assertIsInstance(source_args[0], ast.Name)
                self.assertEqual(source_args[0].id, 'expected_source')



if __name__ == '__main__':
    unittest.main(verbosity=2)
