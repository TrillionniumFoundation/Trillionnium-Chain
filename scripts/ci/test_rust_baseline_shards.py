"""Real local files/Git/failed children; these controls do not run native Rust."""
import argparse
from collections import Counter
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import rust_baseline_shards as shards
from check_ci_contract import code_lines


class RustShardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / 'source'
        self.root.mkdir()
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=self.root, text=True,
                                           stderr=subprocess.DEVNULL).strip()
        self.git = git
        git('init', '-b', 'source')
        git('config', 'user.name', 'Rust shard source fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        self.full = (shards.ROOT / 'scripts/ci/ci_job.sh').read_text()
        path = self.root / 'scripts/ci/ci_job.sh'
        path.parent.mkdir(parents=True)
        path.write_text(self.full)
        git('add', '.')
        git('commit', '-m', 'real source fixture')
        self.head = git('rev-parse', 'HEAD')
        self.args = argparse.Namespace(kind='head', candidate=self.head, tested=self.head,
            base=None, shard='runtime', output=self.home / 'run/rust-shard.json')
        self.expected = shards.identity(self.args, self.root)
        self.run = {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}
        self.scripts = shards.recipes(self.root)
        self.folder = self.home / 'artifacts'
        self.reset_artifacts()

    def reset_artifacts(self):
        if self.folder.exists():
            shutil.rmtree(self.folder)
        self.folder.mkdir()
        self.paths = {}
        for shard in shards.SHARDS:
            directory = self.folder / ('rust-shard-' + self.expected['kind'] + '-' + self.head + '-2-' + shard)
            directory.mkdir()
            command = self.scripts[shard].encode()
            (directory / 'rust-shard.sh').write_bytes(command)
            row = dict(schema=shards.SCHEMA, shard=shard, status='passed', exit_code=0,
                command_sha256=shards.digest(command), run=self.run,
                before=self.expected, after=self.expected)
            self.paths[shard] = directory / 'rust-shard.json'
            self.paths[shard].write_text(json.dumps(row))

    def validate(self, dependency='success'):
        return shards.validate_fanin(self.folder, self.expected, self.run, dependency, self.scripts)

    def test_full_local_lane_and_hosted_command_union_are_exact(self):
        full = re.search(r'(?ms)^  rust-baseline\)\n(.*?)(?=^    ;;$)', self.full)[1]
        actual = [line for script in self.scripts.values() for line in code_lines(script)[2:]]
        self.assertEqual(Counter(actual), Counter(code_lines(full)))
        self.assertEqual(sum(re.search(r'(?:^| )cargo test ', line) is not None for line in actual), 6)
        self.assertEqual(sum('--exact --ignored --nocapture --test-threads=1' in line for line in actual), 4)
        self.assertIn('cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings', actual)
        for before, after in [('cargo fmt ', 'true # cargo fmt '),
                              ('cargo test --locked ', 'cargo test --unlocked '),
                              ('--exact --ignored --nocapture', '--exact --nocapture'),
                              ('python3 formal/pon-nakamoto-v1/test_account_multiproof_oracle.py -v', 'true')]:
            with self.subTest(before=before):
                self.assertIn(before, full)
                changed = self.full.replace(full, full.replace(before, after, 1), 1)
                (self.root / 'scripts/ci/ci_job.sh').write_text(changed)
                with self.assertRaises(ValueError):
                    shards.recipes(self.root)
        (self.root / 'scripts/ci/ci_job.sh').write_text(self.full)

    def test_two_complete_current_source_receipts_are_required(self):
        self.validate()
        for state in ('failure', 'cancelled', 'skipped', '', 'success '):
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.validate(state)
        for shard in shards.SHARDS:
            self.reset_artifacts()
            self.paths[shard].unlink()
            with self.subTest(missing=shard), self.assertRaises(ValueError):
                self.validate()

    def test_partial_wrong_source_attempt_false_zero_and_unexpected_fields_refuse(self):
        mutations = [lambda r: r.update(status='running'), lambda r: r.update(status='skipped'),
            lambda r: r.update(exit_code=False), lambda r: r.update(exit_code=1),
            lambda r: r.update(run={**self.run, 'GITHUB_RUN_ATTEMPT': '1'}),
            lambda r: r['after'].update(tested_tree='0' * 40),
            lambda r: r['before'].update(tracked_worktree_verified=1),
            lambda r: r['before'].update(tracked_entries=float(r['before']['tracked_entries'])),
            lambda r: r.update(error='failed before completion'), lambda r: r.pop('after')]
        for mutate in mutations:
            self.reset_artifacts()
            row = copy.deepcopy(json.loads(self.paths['quality'].read_text()))
            mutate(row)
            self.paths['quality'].write_text(json.dumps(row))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate()

    def test_missing_extra_alias_duplicate_json_and_changed_script_refuse(self):
        for mode in ('extra', 'symlink', 'duplicate', 'oversize', 'script'):
            self.reset_artifacts()
            path = self.paths['runtime']
            if mode == 'extra':
                (self.folder / 'old-run-quality').mkdir()
            elif mode == 'symlink':
                path.rename(path.with_suffix('.old'))
                path.symlink_to(path.with_suffix('.old'))
            elif mode == 'duplicate':
                path.write_text('{"status":"passed","status":"passed"}')
            elif mode == 'oversize':
                path.write_text(' ' * 65537)
            else:
                path.with_suffix('.sh').write_text('true\n')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.validate()

    def test_fixed_fd_bounded_read_rejects_growth_symlink_and_special_file(self):
        path = self.home / 'bounded'
        path.write_bytes(b'old')
        self.assertEqual(shards.read_bounded(path, 3), b'old')
        original = os.fstat
        def grow(fd):
            before = original(fd)
            if before.st_size == 3:
                with path.open('ab') as stream:
                    stream.write(b'x' * 65536)
            return before
        with patch.object(shards.os, 'fstat', side_effect=grow), self.assertRaises(ValueError):
            shards.read_bounded(path, 3)
        alias = self.home / 'alias'
        alias.symlink_to(path)
        with self.assertRaises(ValueError):
            shards.read_bounded(alias)
        fifo = self.home / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            shards.read_bounded(fifo)

    def test_actual_two_parent_merge_identity_and_receipts_cannot_be_relabelled(self):
        base = self.head
        self.git('checkout', '-b', 'candidate')
        (self.root / 'candidate').write_text('candidate')
        self.git('add', '.')
        self.git('commit', '-m', 'candidate')
        candidate = self.git('rev-parse', 'HEAD')
        self.git('checkout', 'source')
        self.git('merge', '--no-ff', '-s', 'ort', '-m', 'actual prospective merge', candidate)
        self.head = self.git('rev-parse', 'HEAD')
        self.args.kind, self.args.candidate = 'prospective-merge', candidate
        self.args.base, self.args.tested = base, self.head
        self.expected = shards.identity(self.args, self.root)
        self.assertEqual(self.git('show', '-s', '--format=%P', self.head).split(), [base, candidate])
        self.reset_artifacts()
        self.validate()
        for name, value in [('base', candidate), ('candidate', base), ('kind', 'head')]:
            changed = copy.copy(self.args)
            setattr(changed, name, value)
            with self.subTest(name=name), self.assertRaises(ValueError):
                shards.identity(changed, self.root)
        row = json.loads(self.paths['runtime'].read_text())
        row['after']['kind'] = 'head'
        self.paths['runtime'].write_text(json.dumps(row))
        with self.assertRaises(ValueError):
            self.validate()

    def child(self, body):
        tools = self.home / 'tools'
        tools.mkdir()
        bash = tools / 'bash'
        bash.write_text('#!/bin/sh\n' + body)
        bash.chmod(0o755)
        return dict(os.environ, **self.run, PATH=str(tools) + os.pathsep + os.environ['PATH'])

    def test_actual_nonzero_child_retains_failure_and_cannot_fan_in(self):
        # The real failed shim prevents native Rust execution in this fixture.
        with patch.dict(os.environ, self.child('exit 7\n'), clear=True):
            self.assertEqual(shards.run_shard(self.args, self.root), 7)
        row = json.loads(self.args.output.read_text())
        self.assertEqual((row['status'], row['exit_code']), ('failed', 7))
        self.assertEqual(row['before'], row['after'])

    def test_real_child_source_mutation_keeps_zero_process_code_but_fails_owner(self):
        file = self.root / 'scripts/ci/ci_job.sh'
        environment = self.child('printf changed >> "$SHARD_TEST_SOURCE"\nexit 0\n')
        environment['SHARD_TEST_SOURCE'] = str(file)
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(shards.run_shard(self.args, self.root), 1)
        row = json.loads(self.args.output.read_text())
        self.assertEqual(row['exit_code'], 0)
        self.assertEqual(row['status'], 'failed')
        self.assertIn('error', row)


if __name__ == '__main__':
    unittest.main()
