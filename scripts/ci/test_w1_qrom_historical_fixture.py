#!/usr/bin/env python3
"""Actual Git and isolated-file controls for the historical W1 materializer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_qrom_historical_fixture as historical
import w1_qrom_implementation_audit as audit


class HistoricalFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='w1-historical-control-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.run_git('init', '--quiet')
        self.run_git('config', 'user.name', 'Historical fixture control')
        self.run_git('config', 'user.email', 'historical-fixture@example.invalid')
        self.original = b'original historical source\n'
        (self.repo / 'source.rs').write_bytes(self.original)
        self.run_git('add', 'source.rs')
        self.run_git('commit', '--quiet', '-m', 'Original source')
        self.commit = self.run_git('rev-parse', 'HEAD').decode().strip()
        self.row = {'path': 'source.rs', 'bytes': len(self.original),
                    'sha256': hashlib.sha256(self.original).hexdigest()}

    def run_git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo,
                                       stderr=subprocess.PIPE, timeout=15)

    def test_historical_blob_ignores_changed_worktree_and_new_head(self):
        (self.repo / 'source.rs').write_bytes(b'new current source\n')
        self.run_git('add', 'source.rs')
        self.run_git('commit', '--quiet', '-m', 'Later source')
        raw, receipt = historical.read_project_blob(self.repo, self.commit, self.row)
        self.assertEqual(raw, self.original)
        self.assertEqual(receipt['git_mode'], '100644')
        self.assertEqual(receipt['git_blob_oid'], self.run_git(
            'rev-parse', self.commit + ':source.rs').decode().strip())
        self.assertNotEqual(raw, (self.repo / 'source.rs').read_bytes())

    def test_missing_commit_never_falls_back_to_present_worktree(self):
        self.assertTrue((self.repo / 'source.rs').exists())
        with self.assertRaises(subprocess.CalledProcessError):
            historical.historical_project_file(self.repo, '0' * 40, self.row)

    def test_wrong_size_digest_path_and_commit_type_are_refused(self):
        for key, value in (('bytes', len(self.original) + 1), ('sha256', '0' * 64),
                           ('path', 'missing.rs'), ('bytes', True), ('path', '../source.rs')):
            with self.subTest(field=key, value=value):
                changed = {**self.row, key: value}
                with self.assertRaises(audit.AuditError):
                    historical.read_project_blob(self.repo, self.commit, changed)
        blob = self.run_git('rev-parse', self.commit + ':source.rs').decode().strip()
        with self.assertRaisesRegex(audit.AuditError, 'not a commit'):
            historical.read_project_blob(self.repo, blob, self.row)

    def test_git_symlink_entry_is_refused_even_with_matching_bytes(self):
        (self.repo / 'link.rs').symlink_to('source.rs')
        self.run_git('add', 'link.rs')
        self.run_git('commit', '--quiet', '-m', 'Symlink is not source')
        commit = self.run_git('rev-parse', 'HEAD').decode().strip()
        raw = b'source.rs'
        row = {'path': 'link.rs', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        with self.assertRaisesRegex(audit.AuditError, 'not a regular Git blob'):
            historical.read_project_blob(self.repo, commit, row)

    def test_git_replace_cannot_substitute_the_historical_object(self):
        original_blob = self.run_git('rev-parse', self.commit + ':source.rs').decode().strip()
        (self.repo / 'source.rs').write_bytes(b'replacement with a different size\n')
        replacement = self.run_git('hash-object', '-w', 'source.rs').decode().strip()
        self.run_git('replace', original_blob, replacement)
        self.assertNotEqual(self.run_git('cat-file', 'blob', original_blob), self.original)
        self.assertEqual(historical.historical_project_file(self.repo, self.commit, self.row),
                         self.original)

    def test_exact_real_historical_mapping_keeps_current_tree_unqualified(self):
        report, receipt = historical.historical_mapping(audit.ROOT)
        self.assertEqual(report['source_base_commit'], 'cb114b13bf848a77634e40a08b31b30c7c758e7b')
        self.assertEqual(report['qualification'], audit.QUALIFICATION)
        self.assertEqual(receipt['historical_source_commit'], report['source_base_commit'])
        self.assertEqual([{key: row[key] for key in ('path', 'bytes', 'sha256')}
                          for row in receipt['project_files']], report['project_files'])
        self.assertIs(receipt['current_project_mapping'], False)
        self.assertIs(receipt['historical_full_repository_checked'], False)
        self.assertIs(receipt['fresh_cryptographic_verification'], False)
        refusal = historical.current_v1_refusal(audit.ROOT)
        self.assertEqual(refusal['result'], 'INPUT_REJECTED')
        self.assertEqual(refusal['reason'], historical.CURRENT_REFUSAL)
        self.assertIs(refusal['current_source_mapping_performed'], False)

    def test_original_reader_acceptance_is_not_a_current_refusal(self):
        _, files, _ = historical.fixture_inputs(audit.ROOT)
        fixture = self.root / 'original-files'
        for name, raw in files.items():
            target = fixture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        reader = fixture / historical.READER
        reader.write_bytes((audit.ROOT / historical.READER).read_bytes())
        with self.assertRaisesRegex(audit.AuditError, 'unexpectedly accepted'):
            historical.current_v1_refusal(fixture)
        missing = fixture / audit.FIXTURE / 'succinct.bin'
        missing.unlink()
        with self.assertRaises(OSError):
            historical.current_v1_refusal(fixture)

    def test_cli_publishes_three_separate_scopes_and_never_overwrites(self):
        out = self.root / 'observations'
        out.mkdir()
        argv = [sys.executable, str(audit.ROOT / 'scripts/w1_qrom_historical_fixture.py'),
                '--repo-root', str(audit.ROOT), '--output-dir', str(out)]
        completed = subprocess.run(argv, text=True, capture_output=True, timeout=45,
                                   env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        saved = {name: (out / name).read_bytes() for name in historical.OUTPUT_NAMES}
        self.assertEqual(json.loads(saved['historical-source.json'])['schema'],
                         historical.MATERIALIZATION_SCHEMA)
        self.assertEqual(json.loads(saved['current-v1-refusal.json'])['schema'],
                         historical.REFUSAL_SCHEMA)
        again = subprocess.run(argv, text=True, capture_output=True, timeout=45)
        self.assertEqual(again.returncode, 2)
        self.assertIn('will not be replaced', again.stderr)
        self.assertEqual(saved, {name: (out / name).read_bytes() for name in historical.OUTPUT_NAMES})


if __name__ == '__main__':
    unittest.main()
