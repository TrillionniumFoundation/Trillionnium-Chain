"""Real Git/worktree counterexamples for source-only identity observations."""
from __future__ import annotations

import hashlib
import gzip
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import capture_chain_hepta_identity as identity


class CaptureIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='chain-hepta-identity-control-')
        self.addCleanup(temporary.cleanup)
        self.area = Path(temporary.name).resolve()
        self.chain = self.area / 'chain'
        self.hepta = self.area / 'hepta'
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_SYSTEM=os.devnull, LC_ALL='C')
        for root in (self.chain, self.hepta):
            root.mkdir()
            self.git(root, 'init', '--quiet', '--initial-branch=main', '--template=')
            self.git(root, 'config', 'user.name', 'Identity control')
            self.git(root, 'config', 'user.email', 'fixture@example.invalid')
            self.git(root, 'config', 'commit.gpgsign', 'false')
            self.git(root, 'config', 'core.hooksPath', os.devnull)
            (root / 'src').mkdir()
            (root / 'src/main.rs').write_text('initial\n')
        (self.chain / 'trillionnium').mkdir()
        (self.chain / 'trillionnium/Cargo.lock').write_text('lock-a\n')
        (self.hepta / 'codex-rs').mkdir()
        (self.hepta / 'codex-rs/Cargo.lock').write_text('lock-b\n')
        (self.hepta / 'MODULE.bazel.lock').write_text('{}\n')
        self.chain_sha = self.commit(self.chain)
        self.hepta_sha = self.commit(self.hepta)

    def git(self, root, *args):
        return subprocess.check_output(['git', '-C', str(root), *args],
                                       env=self.env, stderr=subprocess.PIPE).decode().strip()

    def commit(self, root):
        self.git(root, 'add', '.')
        self.git(root, 'commit', '--quiet', '--no-gpg-sign', '-m', 'fixture source')
        return self.git(root, 'rev-parse', 'HEAD')

    def pair(self, **overrides):
        arguments = dict(chain_root=self.chain, chain_sha=self.chain_sha,
                         hepta_root=self.hepta, hepta_sha=self.hepta_sha)
        arguments.update(overrides)
        return identity.capture_pair(**arguments)

    def chain_observation(self, **overrides):
        return self.pair(**overrides)['source_observations']['chain']

    def assert_chain_refused(self, **overrides):
        report = self.pair(**overrides)
        self.assertIs(report['source_observations']['chain']['tracked_worktree_verified'], False)
        self.assertIn('chain:SOURCE_NOT_VERIFIED', report['blockers'])
        self.assertEqual(report['status'], 'HOLD_NO_GO')
        self.assertIs(report['production_qualified'], False)
        return report

    def test_clean_pinned_sources_and_locks_leave_build_load_unknown_and_hold(self):
        report = self.pair()
        for role, root, expected in (('chain', self.chain, self.chain_sha),
                                    ('hepta', self.hepta, self.hepta_sha)):
            observed = report['source_observations'][role]
            self.assertEqual(observed['source_status'], 'VERIFIED')
            self.assertIs(observed['tracked_worktree_verified'], True)
            self.assertIs(observed['dirty'], False)
            self.assertEqual(observed['errors'], [])
            self.assertEqual(report['source_pair'][role]['sha'], expected)
            self.assertEqual(report['source_pair'][role]['tree'], self.git(root, 'rev-parse', expected + '^{tree}'))
            self.assertTrue(all(value is None for value in report['build_load'][role].values()))
        self.assertEqual(report['source_pair']['chain']['locks']['trillionnium/Cargo.lock'],
                         hashlib.sha256((self.chain / 'trillionnium/Cargo.lock').read_bytes()).hexdigest())
        self.assertEqual(set(report['source_pair']['hepta']['locks']), {'codex-rs/Cargo.lock', 'MODULE.bazel.lock'})
        self.assertEqual(report['build_load_status'], 'NOT_OBSERVED')
        self.assertEqual(report['toolchain_status'], 'NOT_OBSERVED')
        self.assertEqual(report['status'], 'HOLD_NO_GO')
        self.assertIs(report['actual_model_execution_proved'], False)
        self.assertIn('chain:BUILD_NOT_OBSERVED', report['blockers'])
        self.assertIn('hepta:LOAD_NOT_OBSERVED', report['blockers'])

    def test_capture_does_not_create_or_rewrite_repository_files(self):
        def snapshot():
            return {str(p.relative_to(self.area)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in self.area.rglob('*') if p.is_file()}
        before = snapshot()
        self.pair()
        self.assertEqual(snapshot(), before)

    def test_noncanonical_sha_and_missing_commit_never_become_a_pin(self):
        for value in ('main', self.chain_sha[:12], self.chain_sha.upper(),
                      self.chain_sha + ' ', 'f' * 40):
            with self.subTest(value=value):
                report = self.assert_chain_refused(chain_sha=value)
                self.assertEqual(report['source_observations']['chain']['source_status'], 'UNKNOWN')
                self.assertIsNone(report['source_pair']['chain']['sha'])

    def test_different_actual_head_is_reported_and_cannot_borrow_expected_sha(self):
        (self.chain / 'src/main.rs').write_text('changed\n')
        current = self.commit(self.chain)
        report = self.assert_chain_refused()
        self.assertEqual(report['source_pair']['chain']['sha'], current)
        self.assertNotEqual(current, self.chain_sha)
        self.assertTrue(any(e['reason'] == 'HEAD_MISMATCH' for e in report['source_observations']['chain']['errors']))

    def test_same_size_restored_mtime_and_assume_unchanged_do_not_hide_bytes(self):
        source = self.chain / 'src/main.rs'
        original = source.stat()
        self.git(self.chain, 'update-index', '--assume-unchanged', 'src/main.rs')
        source.write_text('altered\n')
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(source.stat().st_size, original.st_size)
        self.assertEqual(source.stat().st_mtime_ns, original.st_mtime_ns)
        self.assertEqual(self.git(self.chain, 'status', '--porcelain'), '')
        report = self.assert_chain_refused()
        detail = report['source_observations']['chain']
        self.assertIs(detail['raw_tracked_entries_match'], False)
        self.assertTrue(any(e.get('path') == 'src/main.rs' for e in detail['errors']))

    def test_executable_mode_is_checked_even_when_git_filemode_is_disabled(self):
        self.git(self.chain, 'config', 'core.filemode', 'false')
        (self.chain / 'src/main.rs').chmod(0o755)
        self.assertEqual(self.git(self.chain, 'status', '--porcelain'), '')
        self.assert_chain_refused()

    def test_modified_lock_keeps_actual_digest_but_source_refuses(self):
        lock = self.chain / 'trillionnium/Cargo.lock'
        lock.write_text('lock-x\n')
        report = self.assert_chain_refused()
        self.assertEqual(report['source_pair']['chain']['locks']['trillionnium/Cargo.lock'],
                         hashlib.sha256(lock.read_bytes()).hexdigest())
        self.assertTrue(any(e['reason'] == 'LOCK_NOT_VERIFIED'
                            for e in report['source_observations']['chain']['errors']))

    def test_all_recognized_tracked_locks_and_explicit_custom_lock_are_observed(self):
        names = ('yarn.lock', 'pnpm-lock.yaml', 'package-lock.json', 'custom.dependencies')
        for name in names:
            (self.chain / name).write_text('dependency version 1\n')
        self.chain_sha = self.commit(self.chain)
        report = self.pair(chain_locks=['custom.dependencies'])
        self.assertIs(report['source_observations']['chain']['tracked_worktree_verified'], True)
        self.assertEqual(set(report['source_pair']['chain']['locks']),
                         set(names) | {'trillionnium/Cargo.lock'})

    def test_missing_explicit_lock_is_null_and_blocks_source(self):
        report = self.assert_chain_refused(chain_locks=['missing/Cargo.lock'])
        self.assertIsNone(report['source_pair']['chain']['locks']['missing/Cargo.lock'])

    def test_explicit_lock_paths_cannot_escape_or_enter_git_metadata(self):
        for path in ('../outside.lock', '/tmp/outside.lock', 'src/../Cargo.lock',
                     './trillionnium/Cargo.lock', 'trillionnium//Cargo.lock', '.git/config'):
            with self.subTest(path=path):
                report = self.assert_chain_refused(chain_locks=[path])
                self.assertEqual(report['source_observations']['chain']['source_status'], 'UNKNOWN')

    def test_root_symlink_alias_and_symlinked_ancestor_are_refused(self):
        alias = self.area / 'alias'
        alias.symlink_to(self.chain, target_is_directory=True)
        self.assert_chain_refused(chain_root=alias)
        ancestor = self.area / 'ancestor'
        ancestor.symlink_to(self.area, target_is_directory=True)
        self.assert_chain_refused(chain_root=ancestor / 'chain')

    def test_regular_entry_replaced_by_symlink_cannot_use_matching_external_bytes(self):
        outside = self.area / 'outside.rs'
        outside.write_bytes((self.chain / 'src/main.rs').read_bytes())
        (self.chain / 'src/main.rs').unlink()
        (self.chain / 'src/main.rs').symlink_to(outside)
        report = self.assert_chain_refused()
        row = next(r for r in report['source_observations']['chain']['mismatched_entries'] if r['path'] == 'src/main.rs')
        self.assertNotIn('observed', row)
        self.assertIn('links are not followed', row['error'])

    def test_tracked_symlink_target_bytes_and_mode_are_observed_without_following(self):
        (self.chain / 'link.rs').symlink_to('src/main.rs')
        self.chain_sha = self.commit(self.chain)
        report = self.pair()
        self.assertIs(report['source_observations']['chain']['tracked_worktree_verified'], True)
        row = next(r for r in report['source_observations']['chain']['entries'] if r['path'] == 'link.rs')
        self.assertEqual(row['observed']['mode'], '120000')
        self.assertEqual(row['observed']['sha256'], hashlib.sha256(b'src/main.rs').hexdigest())
        self.assertEqual(row['observed']['blob'], row['expected']['blob'])
        self.assertIsNone(report['build_load']['chain']['load_sha256'])

    def test_changed_symlink_target_of_same_length_is_refused(self):
        link = self.chain / 'link.rs'
        link.symlink_to('src/main.rs')
        self.chain_sha = self.commit(self.chain)
        link.unlink()
        link.symlink_to('src/else.rs')
        self.assert_chain_refused()

    def test_expected_symlink_replaced_by_regular_target_text_is_refused(self):
        link = self.chain / 'link.rs'
        link.symlink_to('src/main.rs')
        self.chain_sha = self.commit(self.chain)
        link.unlink()
        link.write_bytes(b'src/main.rs')
        self.assert_chain_refused()

    def test_escaping_symlink_is_only_literal_target_bytes_and_never_a_read(self):
        target = '../../missing-outside-target'
        (self.chain / 'link.rs').symlink_to(target)
        self.chain_sha = self.commit(self.chain)
        report = self.pair()
        self.assertIs(report['source_observations']['chain']['tracked_worktree_verified'], True)
        row = next(r for r in report['source_observations']['chain']['entries'] if r['path'] == 'link.rs')
        self.assertEqual(row['observed']['sha256'], hashlib.sha256(target.encode()).hexdigest())
        self.assertEqual(report['build_load_status'], 'NOT_OBSERVED')
        self.assertEqual(report['status'], 'HOLD_NO_GO')

    def test_symlink_lock_does_not_impersonate_read_dependency_content(self):
        (self.chain / 'custom.lock').symlink_to('trillionnium/Cargo.lock')
        self.chain_sha = self.commit(self.chain)
        report = self.assert_chain_refused()
        self.assertIs(report['source_observations']['chain']['raw_tracked_entries_match'], True)
        self.assertIsNone(report['source_pair']['chain']['locks']['custom.lock'])

    def test_gitlink_is_explicitly_unknown_not_silently_skipped(self):
        self.git(self.chain, 'update-index', '--add', '--cacheinfo',
                 '160000,' + self.hepta_sha + ',submodule')
        self.git(self.chain, 'commit', '--quiet', '--no-gpg-sign', '-m', 'gitlink fixture')
        self.chain_sha = self.git(self.chain, 'rev-parse', 'HEAD')
        report = self.assert_chain_refused()
        observed = report['source_observations']['chain']
        self.assertEqual(observed['source_status'], 'UNKNOWN')
        row = next(r for r in observed['mismatched_entries'] if r['path'] == 'submodule')
        self.assertEqual(row['observation_status'], 'UNKNOWN')

    def test_external_gzip_keeps_exact_complete_manifest_and_unchanged_digest_definition(self):
        full = self.pair()
        output = self.area / 'manifests'
        output.mkdir()
        compact = self.pair(manifest_directory=output)
        for role in ('chain', 'hepta'):
            observed = compact['source_observations'][role]
            self.assertNotIn('entries', observed)
            self.assertEqual(observed['mismatched_entries'], [])
            retained = observed['tracked_manifest']
            compressed = (output / retained['path']).read_bytes()
            raw = gzip.decompress(compressed)
            expected = json.dumps(full['source_observations'][role]['entries'],
                                  sort_keys=True, separators=(',', ':')).encode()
            self.assertEqual(raw, expected)
            self.assertEqual(hashlib.sha256(compressed).hexdigest(), retained['sha256'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), observed['tracked_manifest_sha256'])
            self.assertEqual(observed['tracked_manifest_sha256'],
                             full['source_observations'][role]['tracked_manifest_sha256'])

    def test_manifest_output_cannot_mutate_either_source_repository(self):
        for root in (self.chain, self.hepta):
            with self.subTest(root=root), self.assertRaises(identity.IdentityError):
                self.pair(manifest_directory=root)
        self.assertEqual(self.git(self.chain, 'status', '--porcelain'), '')
        self.assertEqual(self.git(self.hepta, 'status', '--porcelain'), '')

    def test_existing_gzip_evidence_is_never_replaced(self):
        output = self.area / 'manifests'
        output.mkdir()
        original = output / 'chain-tracked-manifest-v1.json.gz'
        original.write_bytes(b'retained earlier observation')
        report = self.assert_chain_refused(manifest_directory=output)
        self.assertEqual(original.read_bytes(), b'retained earlier observation')
        self.assertEqual(report['source_observations']['chain']['source_status'], 'UNKNOWN')

    def test_symlinked_source_parent_cannot_escape_the_worktree(self):
        outside = self.area / 'outside-dir'
        (self.chain / 'src').rename(outside)
        (self.chain / 'src').symlink_to(outside, target_is_directory=True)
        self.assert_chain_refused()

    def test_git_replace_cannot_change_tree_meaning_and_is_itself_refused(self):
        original_tree = self.git(self.chain, 'rev-parse', self.chain_sha + '^{tree}')
        (self.chain / 'src/main.rs').write_text('replacement\n')
        replacement = self.commit(self.chain)
        self.git(self.chain, 'checkout', '--quiet', '--detach', self.chain_sha)
        self.git(self.chain, 'replace', self.chain_sha, replacement)
        self.assertNotEqual(self.git(self.chain, 'rev-parse', self.chain_sha + '^{tree}'), original_tree)
        report = self.assert_chain_refused()
        self.assertEqual(report['source_pair']['chain']['tree'], original_tree)
        self.assertTrue(any(e['reason'] == 'REPLACEMENT_REFS_PRESENT'
                            for e in report['source_observations']['chain']['errors']))

    def test_inherited_git_environment_cannot_select_another_repository(self):
        with patch.dict(os.environ, {'GIT_DIR': str(self.hepta / '.git'),
                                     'GIT_WORK_TREE': str(self.hepta),
                                     'GIT_CONFIG_COUNT': '1',
                                     'GIT_CONFIG_KEY_0': 'core.fsmonitor',
                                     'GIT_CONFIG_VALUE_0': 'false'}):
            report = self.pair()
        self.assertIs(report['source_observations']['chain']['tracked_worktree_verified'], True)
        self.assertEqual(report['source_pair']['chain']['sha'], self.chain_sha)

    def test_staged_index_cannot_disagree_even_when_worktree_bytes_match(self):
        source = self.chain / 'src/main.rs'
        original = source.read_bytes()
        source.write_text('other staged source\n')
        self.git(self.chain, 'add', 'src/main.rs')
        source.write_bytes(original)
        report = self.assert_chain_refused()
        observed = report['source_observations']['chain']
        self.assertIs(observed['raw_tracked_entries_match'], True)
        self.assertIs(observed['index_matches'], False)

    def test_ignored_untracked_input_is_preserved_as_a_blocker(self):
        (self.chain / '.gitignore').write_text('ignored-input\n')
        self.chain_sha = self.commit(self.chain)
        (self.chain / 'ignored-input').write_text('untracked build input\n')
        self.assertEqual(self.git(self.chain, 'status', '--porcelain'), '')
        report = self.assert_chain_refused()
        self.assertIn('ignored-input', report['source_observations']['chain']['untracked_paths_including_ignored'])


if __name__ == '__main__':
    unittest.main()
