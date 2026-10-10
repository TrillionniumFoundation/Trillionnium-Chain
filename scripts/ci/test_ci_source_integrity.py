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


if __name__ == '__main__':
    unittest.main(verbosity=2)
