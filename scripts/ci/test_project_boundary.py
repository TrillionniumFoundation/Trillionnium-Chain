#!/usr/bin/env python3
"""Exercise the real preflight in isolated Git fixtures, never against a remote.

The one-package manifests below are boundary-test inputs, not a reconstructed
workspace or native qualification. No network command, user hook or credential
is used. The same entry point is exercised in dev/audit/staged/push modes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BRANCH = 'fix/chain-boundary-regression'
HTTPS = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain'
ORIGINS = (HTTPS, HTTPS + '.git', 'git@github.com:TrillionniumFoundation/Trillionnium-Chain.git')


class ProjectBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pon-boundary-regression-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GIT_')}
        self.env.update(HOME=str(self.root), GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
                        PYTHONDONTWRITEBYTECODE='1')
        for name in ('scripts/project-preflight.sh', 'scripts/ci/project_boundary.py'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.policy = {
            'canonical_repository': 'TrillionniumFoundation/Trillionnium-Chain',
            'lane': 'chain-consensus',
            'consensus': {'production_consensus_activation': False,
                          'development_target': 'pon-nakamoto-v1'},
            'repository': {'required_pull_request_reviews': 0,
                           'require_code_owner_review': False,
                           'require_last_push_approval': False,
                           'block_force_push': True, 'block_branch_deletion': True},
            'branch': {'protected': ['main'],
                       'development_regex': r'^(feature|fix|chore|docs|test)/chain-[a-z0-9][a-z0-9._-]*$'},
        }
        self.write_policy()
        self.write('PROJECT_ID', 'trillionnium-chain\n')
        self.write('trillionnium/Cargo.toml', '[workspace]\nmembers = ["crates/fixture"]\n')
        self.write('trillionnium/crates/fixture/Cargo.toml',
                   '[package]\nname = "fixture"\nversion = "0.0.0"\n')
        self.write('config/portability-inventory-v1.json',
                   json.dumps({'packages': [{'package': 'fixture'}]}))
        self.git('init', '-b', BRANCH)
        self.git('config', 'user.name', 'Boundary regression fixture')
        self.git('config', 'user.email', 'boundary-regression@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'core.hooksPath', os.devnull)
        self.git('remote', 'add', 'origin', HTTPS)
        self.git('add', '.')
        self.git('commit', '-m', 'Boundary fixture base')
        self.old = self.git('rev-parse', 'HEAD')
        self.write('fixture-marker', 'second commit\n')
        self.git('add', 'fixture-marker')
        self.git('commit', '-m', 'Boundary fixture next')
        self.head = self.git('rev-parse', 'HEAD')

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')

    def write_policy(self):
        self.write('PROJECT_BOUNDARY.json', json.dumps(self.policy))

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, env=self.env,
                              text=True, capture_output=True, check=True,
                              timeout=10).stdout.strip()

    def update(self, *, old=None, sha=None, remote=None):
        return (f'refs/heads/{BRANCH} {sha or self.head} '
                f'{remote or "refs/heads/" + BRANCH} {self.old if old is None else old}\n')

    def preflight(self, mode='--audit', *, target=HTTPS, remote='origin', updates=''):
        return subprocess.run(['bash', 'scripts/project-preflight.sh', mode, remote, target],
                              cwd=self.root, env=self.env, text=True, input=updates,
                              capture_output=True, timeout=10)

    def passed(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['result'], 'PASS')
        self.assertIs(report['remote_policy_mutated'], False)

    def rejected(self, result, reason):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(reason, result.stderr)
        self.assertNotIn('"result": "PASS"', result.stdout)

    def test_checkout_https_without_suffix_audits_detached_head(self):
        self.git('checkout', '--detach', self.head)
        self.passed(self.preflight())

    def test_exact_repository_spellings_allow_audit_and_dev(self):
        for origin in ORIGINS:
            for mode in ('--audit', '--dev'):
                with self.subTest(origin=origin, mode=mode):
                    self.git('remote', 'set-url', 'origin', origin)
                    self.passed(self.preflight(mode))

    def test_foreign_or_decorated_origins_are_not_normalized(self):
        for origin in (
            HTTPS.replace('github.com', 'github.com.evil.invalid'),
            HTTPS.replace('TrillionniumFoundation', 'OtherOwner'),
            HTTPS + '-fork.git', HTTPS + '.git/extra', HTTPS + '?ref=main',
            HTTPS + '#main', HTTPS + '/', HTTPS.replace('https:', 'http:'),
            HTTPS.replace('github.com', 'github.com@evil.invalid'),
            'ssh://git@github.com/TrillionniumFoundation/Trillionnium-Chain.git',
            '/tmp/Trillionnium-Chain.git',
        ):
            with self.subTest(origin=origin):
                self.git('remote', 'set-url', 'origin', origin)
                self.rejected(self.preflight(), 'origin mismatch')

    def test_push_hook_accepts_only_canonical_repository_spellings(self):
        for origin in ORIGINS:
            self.git('remote', 'set-url', 'origin', origin)
            for target in ORIGINS:
                with self.subTest(origin=origin, target=target):
                    self.passed(self.preflight('--push', target=target, updates=self.update()))

    def test_push_remote_name_and_destination_still_reject(self):
        self.rejected(self.preflight('--push', remote='other', updates=self.update()),
                      'push target mismatch')
        for target in (HTTPS + '-fork.git', HTTPS + '?ref=main', 'file:///tmp/repo'):
            with self.subTest(target=target):
                self.rejected(self.preflight('--push', target=target, updates=self.update()),
                              'push target mismatch')

    def test_canonical_push_target_does_not_rescue_foreign_origin(self):
        self.git('remote', 'set-url', 'origin', HTTPS + '-fork.git')
        self.rejected(self.preflight('--push', updates=self.update()), 'origin mismatch')

    def test_detached_source_is_audit_only(self):
        self.git('checkout', '--detach', self.head)
        for mode in ('--dev', '--staged', '--push'):
            with self.subTest(mode=mode):
                self.rejected(self.preflight(mode, updates=self.update()),
                              'not an allowed development branch')

    def test_protected_branch_cannot_become_a_development_branch(self):
        self.git('branch', '-m', 'main')
        for mode in ('--dev', '--staged', '--push'):
            with self.subTest(mode=mode):
                self.rejected(self.preflight(mode, updates=self.update()),
                              'not an allowed development branch')

    def test_activation_and_preservation_policy_are_not_relaxed(self):
        self.policy['consensus']['production_consensus_activation'] = True
        self.write_policy()
        self.rejected(self.preflight(), 'activation changed')
        self.policy['consensus']['production_consensus_activation'] = False
        self.policy['repository']['block_force_push'] = False
        self.write_policy()
        self.rejected(self.preflight(), 'remote preservation contract changed')

    def test_staged_and_push_modes_read_their_own_source(self):
        self.policy['consensus']['production_consensus_activation'] = True
        self.write_policy()
        self.rejected(self.preflight('--dev'), 'activation changed')
        self.passed(self.preflight('--staged'))
        self.passed(self.preflight('--push', updates=self.update()))
        self.git('add', 'PROJECT_BOUNDARY.json')
        self.rejected(self.preflight('--staged'), 'activation changed')
        self.passed(self.preflight('--push', updates=self.update()))

    def test_non_fast_forward_update_is_rejected(self):
        unrelated = self.git('commit-tree', self.git('rev-parse', 'HEAD^{tree}'),
                             '-m', 'Unrelated fixture history')
        self.rejected(self.preflight('--push', updates=self.update(old=unrelated)),
                      'non-fast-forward push rejected')

    def test_missing_updates_deletion_and_unchecked_sha_reject(self):
        self.rejected(self.preflight('--push'), 'no exact push updates supplied')
        for sha in ('0' * 40, self.old):
            with self.subTest(sha=sha):
                self.rejected(self.preflight('--push', updates=self.update(sha=sha)),
                              'only checked-out HEAD can be pushed')

    def test_new_branch_must_be_the_checked_out_continuation(self):
        self.passed(self.preflight('--push', updates=self.update(old='0' * 40)))
        self.rejected(self.preflight('--push', updates=self.update(
            old='0' * 40, remote='refs/heads/fix/chain-unrelated')),
            'new continuation must be the checked-out branch')

    def test_protected_remote_branch_and_mixed_updates_reject(self):
        protected = self.update(remote='refs/heads/main')
        self.rejected(self.preflight('--push', updates=protected),
                      'protected/invalid remote branch')
        self.rejected(self.preflight('--push', updates=self.update() + protected),
                      'protected/invalid remote branch')

    def test_source_inventory_and_external_path_dependency_still_reject(self):
        self.write('config/portability-inventory-v1.json', '{"packages":[]}')
        self.rejected(self.preflight(), 'workspace/source inventory mismatch')
        self.write('config/portability-inventory-v1.json',
                   json.dumps({'packages': [{'package': 'fixture'}]}))
        self.write('trillionnium/crates/fixture/Cargo.toml',
                   '[package]\nname="fixture"\nversion="0.0.0"\n'
                   '[dependencies]\nforeign={path="../../../outside"}\n')
        self.rejected(self.preflight(), 'external path dependency')

    def test_checker_does_not_modify_refs_config_or_tracked_files(self):
        before = (self.git('show-ref'), self.git('config', '--local', '--list'),
                  self.git('status', '--porcelain'), self.git('diff', 'HEAD'))
        self.passed(self.preflight())
        self.rejected(self.preflight('--push', updates=self.update(sha='0' * 40)),
                      'only checked-out HEAD can be pushed')
        after = (self.git('show-ref'), self.git('config', '--local', '--list'),
                 self.git('status', '--porcelain'), self.git('diff', 'HEAD'))
        self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main(verbosity=2)
