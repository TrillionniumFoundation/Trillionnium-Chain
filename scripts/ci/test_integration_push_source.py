#!/usr/bin/env python3
"""Real Git controls for the separate integration-push source owner."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import integration_push_source as source
from check_ci_contract import (PUSH_SOURCE_LANES, PUSH_SOURCE_SELECTED,
                               check_integration_push_workflow, check_history_host_call)


class PushSourceControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='push-source-control-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / 'candidate'
        self.root.mkdir()
        self.command(self.root, 'init', '--quiet', '-b', 'main')
        self.command(self.root, 'config', 'user.name', 'Source control')
        self.command(self.root, 'config', 'user.email', 'control@trillionnium.invalid')
        self.before = self.commit('common.txt', 'first\nsecond\nthird\nfourth\nfifth\n')
        self.command(self.root, 'checkout', '-b', source.INTEGRATION_REF.removeprefix('refs/heads/'))
        self.head = self.commit('candidate.txt', 'candidate\n')
        self.command(self.root, 'checkout', 'main')
        self.base = self.commit('base.txt', 'main\n')
        self.command(self.root, 'checkout', '--detach', self.head)
        self.remote = self.directory / 'remote.git'
        self.command(self.directory, 'clone', '--bare', '--quiet', str(self.root), str(self.remote))
        self.event_path = self.directory / 'event.json'
        self.event = {'ref': source.INTEGRATION_REF, 'before': self.before, 'after': self.head,
                      'created': False, 'deleted': False, 'forced': False,
                      'head_commit': {'id': self.head},
                      'repository': {'full_name': source.REPOSITORY, 'id': 123,
                                     'default_branch': 'main'}}
        self.write_event()
        self.environment = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': source.REPOSITORY,
                            'GITHUB_REF': source.INTEGRATION_REF, 'GITHUB_SHA': self.head,
                            'GITHUB_EVENT_PATH': str(self.event_path),
                            'GITHUB_RUN_ID': '1234', 'GITHUB_RUN_ATTEMPT': '1'}
        self.remote_patch = patch.object(source, 'REMOTE', str(self.remote))
        self.remote_patch.start()
        self.addCleanup(self.remote_patch.stop)

    def command(self, root, *arguments):
        return subprocess.check_output(['git', '-C', str(root), *arguments],
                                       env=source.git_environment(), text=True,
                                       stderr=subprocess.PIPE).strip()

    def commit(self, filename, contents):
        (self.root / filename).write_text(contents)
        self.command(self.root, 'add', filename)
        self.command(self.root, 'commit', '--quiet', '-m', filename)
        return self.command(self.root, 'rev-parse', 'HEAD')

    def write_event(self):
        self.event_path.write_text(json.dumps(self.event))

    def resolve(self):
        return source.resolve(root=self.root, environment=self.environment)

    def expected(self, context):
        return dict(self.environment, **{'EXPECTED_' + key.upper(): context[key]
                                        for key in ('head', 'base', 'merge')})

    def worker(self, name):
        worker = self.directory / name
        self.command(self.directory, 'clone', '--quiet', '--no-local', str(self.remote), str(worker))
        self.command(worker, 'checkout', '--detach', self.head)
        return worker

    def test_real_diverged_merge_imports_tree_and_blob_closure(self):
        context = self.resolve()
        self.assertEqual((context['head'], context['base']), (self.head, self.base))
        self.assertFalse(context['is_github_pr_merge'])
        self.assertEqual(context['event']['name'], 'push')
        self.assertEqual(self.command(self.root, 'show', '-s', '--format=%P', context['merge']).split(),
                         [self.base, self.head])
        self.assertNotEqual(context['merge_tree'], self.command(self.root, 'rev-parse', self.head + '^{tree}'))
        self.assertEqual(self.command(self.root, 'ls-tree', '-r', '--name-only', context['merge']).splitlines(),
                         ['base.txt', 'candidate.txt', 'common.txt'])
        self.command(self.root, 'fsck', '--no-reflogs', '--connectivity-only', context['merge'])
        self.assertEqual(self.command(self.root, 'rev-parse', 'HEAD'), self.head)

    def test_independent_head_and_merge_workers_reproduce_one_frozen_source(self):
        context = self.resolve()
        expected = self.expected(context)
        for kind in ('head', 'prospective-merge'):
            with self.subTest(kind=kind):
                root = self.worker('worker-' + kind)
                result = source.materialize(context, source.digest(context), kind,
                                            root=root, environment=expected)
                self.assertEqual(result['context'], context)
                self.assertEqual(result['source']['tested_commit'],
                                 self.head if kind == 'head' else context['merge'])
                self.assertEqual(result['github_sha'], self.head)
                self.assertEqual(result['github_event_name'], 'push')
                self.assertTrue(result['source']['tracked_worktree_verified'])
                self.assertEqual(self.command(root, 'status', '--porcelain'), '')

    def test_fast_forward_tree_still_has_two_ordered_parents(self):
        self.command(self.remote, 'update-ref', 'refs/heads/main', self.before)
        context = self.resolve()
        self.assertEqual(context['merge_tree'], self.command(self.root, 'rev-parse', self.head + '^{tree}'))
        self.assertEqual(self.command(self.root, 'show', '-s', '--format=%P', context['merge']).split(),
                         [self.before, self.head])

    def test_workers_do_not_resolve_a_later_main(self):
        context = self.resolve()
        worker = self.worker('frozen-worker')
        self.command(self.remote, 'update-ref', 'refs/heads/main', self.before)
        result = source.materialize(context, source.digest(context), 'prospective-merge',
                                    root=worker, environment=self.expected(context))
        self.assertEqual(result['source']['base'], self.base)
        self.assertNotEqual(result['source']['base'],
                            self.command(self.remote, 'rev-parse', 'refs/heads/main'))

    def test_conflicts_refuse_without_a_merge_or_candidate_repair(self):
        self.command(self.root, 'checkout', 'main')
        conflict_base = self.commit('candidate.txt', 'conflicting main\n')
        self.command(self.root, 'push', str(self.remote), 'main:main')
        self.command(self.root, 'checkout', '--detach', self.head)
        partial = {}
        with self.assertRaises(subprocess.CalledProcessError):
            source.resolve(root=self.root, environment=self.environment, receipt=partial)
        self.assertEqual(partial['base'], conflict_base)
        self.assertNotIn('merge', partial)
        self.assertEqual(self.command(self.root, 'rev-parse', 'HEAD'), self.head)
        self.assertEqual(self.command(self.root, 'status', '--porcelain'), '')

    def test_real_event_ref_after_repository_and_run_are_not_optional(self):
        for key, value in (('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REPOSITORY', 'other/repo'),
                           ('GITHUB_REF', 'refs/heads/new-workaround'), ('GITHUB_SHA', self.before),
                           ('GITHUB_SHA', 'main'), ('GITHUB_RUN_ID', ''), ('GITHUB_RUN_ATTEMPT', '0')):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                source.event_identity(dict(self.environment, **{key: value}))
        original = copy.deepcopy(self.event)
        for change in ({'after': self.before}, {'before': '0' * 40},
                       {'head_commit': {'id': self.before}}, {'ref': 'refs/tags/candidate'},
                       {'created': True}, {'deleted': True}, {'forced': True},
                       {'created': 0}, {'repository': {'full_name': source.REPOSITORY,
                        'id': 123, 'default_branch': 'other'}}):
            self.event = dict(original, **change)
            self.write_event()
            with self.subTest(change=change), self.assertRaises(ValueError):
                source.event_identity(self.environment)
        with self.assertRaises(ValueError):
            source.load_json('{"after":"a","after":"b"}')

    def test_dirty_or_wrong_candidate_cannot_select_source(self):
        (self.root / 'common.txt').write_text('changed\n')
        with self.assertRaises(ValueError):
            self.resolve()
        self.command(self.root, 'checkout', '--', 'common.txt')
        self.command(self.root, 'checkout', '--detach', self.before)
        with self.assertRaises(ValueError):
            self.resolve()

    def test_context_corruption_and_independent_expected_values_are_refused(self):
        context = self.resolve()
        expected = self.expected(context)
        for key, value in (('head', self.before), ('base', self.before), ('merge', self.head),
                           ('merge_tree', 'a' * 40), ('base_ref', 'refs/heads/other'),
                           ('is_github_pr_merge', True), ('production_activation', True)):
            changed = dict(context, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                source.materialize(changed, source.digest(context), 'head',
                                   root=self.root, environment=expected)
            with self.subTest(key=key, digest='recomputed'), self.assertRaises(ValueError):
                source.materialize(changed, source.digest(changed), 'head',
                                   root=self.root, environment=expected)
        for key in ('EXPECTED_HEAD', 'EXPECTED_BASE', 'EXPECTED_MERGE'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                source.materialize(context, source.digest(context), 'head', root=self.root,
                                   environment=dict(expected, **{key: self.before}))
        changed = copy.deepcopy(context)
        changed['event']['run_attempt'] = '2'
        with self.assertRaises(ValueError):
            source.materialize(changed, source.digest(changed), 'head',
                               root=self.root, environment=expected)
        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
            with self.subTest(replayed=key), self.assertRaises(ValueError):
                source.materialize(context, source.digest(context), 'head', root=self.root,
                                   environment=dict(expected, **{key: '2'}))

    def test_wrong_tree_and_reversed_parent_commit_cannot_borrow_correct_inputs(self):
        context = self.resolve()
        for reverse in (False, True):
            changed = dict(context)
            if reverse:
                changed['merge'] = self.command(self.root, 'commit-tree', context['merge_tree'],
                                                '-p', self.head, '-p', self.base, '-m', 'wrong parents')
            else:
                changed['merge_tree'] = self.command(self.root, 'rev-parse', self.head + '^{tree}')
            with self.subTest(reverse=reverse), self.assertRaisesRegex(ValueError, 'PUSH_REPRODUCED_SOURCE'):
                source.materialize(changed, source.digest(changed), 'head', root=self.root,
                                   environment=self.expected(changed))

    def test_cli_refusal_retains_attempted_context_and_independent_workflow_inputs(self):
        context = self.resolve()
        environment = {**os.environ, **self.expected(context), 'EXPECTED_BASE': 'f' * 40,
                       'PYTHONDONTWRITEBYTECODE': '1'}
        output = self.directory / 'failed-materialization.json'
        process = subprocess.run([
            sys.executable, str(source.ROOT / 'scripts/ci/integration_push_source.py'), 'materialize',
            '--context-json', source.canonical(context), '--context-sha256', source.digest(context),
            '--kind', 'prospective-merge', '--output', str(output)], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        self.assertNotEqual(process.returncode, 0)
        receipt = json.loads(output.read_text())
        self.assertFalse(receipt['completed'])
        self.assertEqual(receipt['error'], 'PUSH_EXPECTED_CONTEXT')
        self.assertEqual(receipt['attempted_context'], context)
        self.assertEqual(receipt['context_sha256'], source.digest(context))
        self.assertEqual(receipt['source_kind'], 'prospective-merge')
        self.assertEqual(receipt['workflow_inputs']['EXPECTED_BASE'], 'f' * 40)
        self.assertEqual(receipt['workflow_inputs']['EXPECTED_HEAD'], self.head)
        self.assertEqual(receipt['workflow_inputs']['EXPECTED_MERGE'], context['merge'])
        self.assertEqual(receipt['workflow_inputs']['GITHUB_RUN_ID'], '1234')
        self.assertEqual(receipt['workflow_inputs']['GITHUB_RUN_ATTEMPT'], '1')
        self.assertEqual(receipt['workflow_inputs']['GITHUB_EVENT_NAME'], 'push')
        self.assertNotIn('source', receipt)

    def test_local_merge_driver_cannot_supply_the_selected_tree(self):
        previous_head = self.head
        self.head = self.commit('common.txt', 'candidate\nsecond\nthird\nfourth\nfifth\n')
        self.command(self.root, 'checkout', 'main')
        self.base = self.commit('common.txt', 'first\nsecond\nthird\nfourth\nmain\n')
        self.command(self.root, 'push', str(self.remote), 'main:main')
        self.command(self.root, 'checkout', '--detach', self.head)
        self.event.update(before=previous_head, after=self.head, head_commit={'id': self.head})
        self.environment['GITHUB_SHA'] = self.head
        self.write_event()
        marker = self.directory / 'driver-ran'
        (self.root / '.git/info/attributes').write_text('* merge=external\n')
        self.command(self.root, 'config', 'merge.external.driver', 'touch ' + str(marker))
        context = self.resolve()
        self.assertFalse(marker.exists())
        self.assertEqual(context['merge_tree'], source._canonical_merge_tree(self.root, self.base, self.head))
        self.assertEqual(self.command(self.root, 'show', context['merge'] + ':common.txt'),
                         'candidate\nsecond\nthird\nfourth\nmain')


class PushWorkflowControls(unittest.TestCase):
    def test_original_matrices_commands_and_pr_sources_keep_the_push_owner(self):
        for name in PUSH_SOURCE_LANES:
            text = (source.ROOT / '.github/workflows' / name).read_text()
            with self.subTest(name=name):
                check_integration_push_workflow(text, name)
                if name == 'pon-priority-acceptance.yml':
                    check_history_host_call(text)

    def test_trigger_resolver_source_and_retention_cannot_be_silently_removed(self):
        for name in PUSH_SOURCE_LANES:
            original = (source.ROOT / '.github/workflows' / name).read_text()
            changes = [
                ('- fix/chain-six-axis-performance-20261103', '- workaround'),
                ('    needs: push-source-context\n', ''),
                ("needs.push-source-context.result == 'success'", "needs.push-source-context.result == 'failure'"),
                ('source: [head, prospective-merge]', 'source: [head]'),
                ('${{ steps.resolve.outputs.base }}', '${{ steps.resolve.outputs.head }}'),
                (PUSH_SOURCE_SELECTED, '${{ github.sha }}'),
                ('--context-sha256 "$PUSH_SOURCE_CONTEXT_SHA256"', ''),
                ('          cp "$RUNNER_TEMP/integration-push-context.json" "$push_context_out/push-source-context.json"\n', ''),
                ('--expected-head "$GITHUB_SHA"', '--expected-head main'),
            ]
            for before, after in changes:
                self.assertIn(before, original)
                with self.subTest(name=name, mutation=before), self.assertRaises(ValueError):
                    check_integration_push_workflow(original.replace(before, after, 1), name)


if __name__ == '__main__':
    unittest.main()
