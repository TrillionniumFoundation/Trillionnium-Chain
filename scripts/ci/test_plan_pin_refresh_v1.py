#!/usr/bin/env python3
"""Check deterministic generation without transferring acceptance or provenance."""
import hashlib
import os
import subprocess
from unittest.mock import patch
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
sys.dont_write_bytecode = True
import refresh_plan_manifest_pins_v1 as pins


class PinRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.text = (pins.ROOT / pins.MANIFEST).read_text()
        data = tomllib.loads(self.text)
        paths = {data[key] for key in pins.PIN_PATH_FIELDS.values()} | set(pins.PIN_FIELDS.values())
        paths |= {data['plan_path'], data['evidence_contract_path']}
        for relative in paths:
            path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture '+relative+'\n')

    def test_idempotent(self):
        once = pins.refresh(self.root, self.text)
        self.assertEqual(pins.refresh(self.root, once), once)

    def test_immutable_provenance_and_activation_fields(self):
        before = tomllib.loads(self.text)
        after = tomllib.loads(pins.refresh(self.root, self.text))
        for key in before:
            if not key.endswith('_git_blob') and key not in ('plan_sha256', 'evidence_contract_sha256'):
                self.assertEqual(before[key], after[key], key)
        self.assertIs(after['production_candidate'], False)
        self.assertIs(after['historical_integration']['acceptance_transferred'], False)

    def test_git_blob_digest(self):
        after = tomllib.loads(pins.refresh(self.root, self.text))
        content = (self.root / after['workspace_manifest_path']).read_bytes()
        expected = hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        self.assertEqual(after['workspace_manifest_git_blob'], expected)

    def test_missing_input_rejects(self):
        data = tomllib.loads(self.text)
        (self.root / data['workspace_manifest_path']).unlink()
        with self.assertRaises(ValueError): pins.refresh(self.root, self.text)

    def test_unknown_pin_rejects(self):
        with self.assertRaises(ValueError):
            pins.refresh(self.root, 'unknown_git_blob = "0"\n'+self.text)

    def test_missing_pin_rejects(self):
        text = '\n'.join(line for line in self.text.splitlines() if not line.startswith('workspace_manifest_git_blob = '))
        with self.assertRaises(ValueError): pins.refresh(self.root, text)

    def test_path_escape_rejects(self):
        text = self.text.replace('workspace_manifest_path = "trillionnium/Cargo.toml"', 'workspace_manifest_path = "../outside"')
        with self.assertRaises(ValueError): pins.refresh(self.root, text)

    def test_symlink_escape_rejects(self):
        data = tomllib.loads(self.text); path = self.root / data['workspace_manifest_path']
        path.unlink(); path.symlink_to('/etc/hosts')
        with self.assertRaises(ValueError): pins.refresh(self.root, self.text)

class SourceAncestryTests(unittest.TestCase):
    def setUp(self):
        import check_plan_manifest_pins_v1 as gate
        self.gate = gate
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {**os.environ, 'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                    'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        self.git('init', '-q'); self.git('commit', '-q', '--allow-empty', '-m', 'baseline')
        self.commit = self.git('rev-parse', 'HEAD'); self.tree = self.git('rev-parse', 'HEAD^{tree}')
        self.binding = {'assessed_commit': self.commit, 'assessed_tree': self.tree}
        self.scope = patch.object(gate, 'ROOT', self.root); self.scope.start(); self.addCleanup(self.scope.stop)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, env=self.env,
                                       stderr=subprocess.DEVNULL, text=True).strip()

    def test_exact_current_baseline(self):
        self.gate.verify_assessed_baseline(self.binding)

    def test_current_baseline_still_requires_ancestry(self):
        self.git('checkout', '-q', '--orphan', 'other')
        self.git('commit', '-q', '--allow-empty', '-m', 'unrelated')
        with self.assertRaises(self.gate.PinError): self.gate.verify_assessed_baseline(self.binding)

    def test_current_baseline_still_requires_exact_tree(self):
        with self.assertRaises(self.gate.PinError):
            self.gate.verify_assessed_baseline({**self.binding, 'assessed_tree': '0'*40})

    def test_missing_current_baseline_cannot_pass(self):
        with self.assertRaises((self.gate.PinError, subprocess.CalledProcessError)):
            self.gate.verify_assessed_baseline({**self.binding, 'assessed_commit': 'f'*40})

    def test_clean_clone_does_not_need_unreachable_historical_objects(self):
        self.assertFalse(self.gate.verify_optional_historical_source('f'*40, self.tree))

    def test_present_history_is_verified(self):
        self.assertTrue(self.gate.verify_optional_historical_source(self.commit, self.tree))

    def test_wrong_historical_tree_still_rejects(self):
        with self.assertRaises(self.gate.PinError):
            self.gate.verify_optional_historical_source(self.commit, '0'*40)


class ChangeScopedPinTests(unittest.TestCase):
    """Only release/source-bound inputs require a pin refresh."""

    def setUp(self):
        import check_plan_manifest_pins_v1 as gate
        self.gate = gate
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {**os.environ, 'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                    'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        self.git('init', '-q')
        (self.root / 'trillionnium').mkdir()
        (self.root / 'trillionnium/Cargo.toml').write_text('[workspace]\n')
        (self.root / 'src.rs').write_text('v1\n')
        self.git('add', '.')
        self.git('commit', '-q', '-m', 'baseline')
        self.snapshot = self.git('rev-parse', 'HEAD')
        self.scope = patch.object(gate, 'ROOT', self.root); self.scope.start(); self.addCleanup(self.scope.stop)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, env=self.env,
                                       stderr=subprocess.DEVNULL, text=True).strip()

    def test_ordinary_source_change_does_not_require_refresh(self):
        (self.root / 'src.rs').write_text('v2\n')
        self.git('add', 'src.rs'); self.git('commit', '-q', '-m', 'ordinary source')
        self.assertEqual(self.gate.changed_pin_paths(self.snapshot, {'trillionnium/Cargo.toml'}), set())

    def test_pinned_input_change_requires_refresh(self):
        (self.root / 'trillionnium/Cargo.toml').write_text('[workspace]\nmembers=[]\n')
        self.git('add', 'trillionnium/Cargo.toml'); self.git('commit', '-q', '-m', 'binding change')
        self.assertEqual(self.gate.changed_pin_paths(self.snapshot, {'trillionnium/Cargo.toml'}),
                         {'trillionnium/Cargo.toml'})

    def test_uncommitted_pinned_input_change_requires_refresh(self):
        (self.root / 'trillionnium/Cargo.toml').write_text('[workspace]\nmembers=[]\n')
        self.assertEqual(self.gate.changed_pin_paths(self.snapshot, {'trillionnium/Cargo.toml'}),
                         {'trillionnium/Cargo.toml'})

    def test_snapshot_refresh_rejects_dirty_worktree(self):
        (self.root / 'dirty.txt').write_text('uncommitted\n')
        with self.assertRaises(ValueError): pins.current_snapshot(self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
