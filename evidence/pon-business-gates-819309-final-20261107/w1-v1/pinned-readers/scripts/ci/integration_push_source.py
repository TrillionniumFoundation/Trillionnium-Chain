#!/usr/bin/env python3
"""Freeze a real integration push and reproduce its canonical merge with main.

This is a separate push source, never a PR event or GitHub-generated PR merge.
The original source verifier remains authoritative for every checked-out lane.
Only the resolver reads the current main ref; workers use its frozen Git objects.
The base is main as observed when that resolver runs, not at push creation time.
Rerun the whole workflow: a failed-job-only rerun must not borrow a prior
attempt's resolver outputs. Separate workflow runs retain separate base snapshots.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from verify_ci_source import _canonical_merge_tree, verify

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
INTEGRATION_REF = 'refs/heads/fix/chain-six-axis-performance-20261103'
BASE_REF = 'refs/heads/main'
REMOTE = 'https://github.com/' + REPOSITORY + '.git'
SCHEMA = 'trnm-integration-push-source-v1'
MERGE_FORMAT = 'canonical-git-merge-tree-ordered-base-head-v1'
CONTEXT_LIMIT = 65536


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'PUSH_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError('PUSH_NONFINITE_JSON_NUMBER:' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{40}', value) is not None


def git_environment():
    # Match the original verifier's isolated merge environment. Neither global
    # configuration, replacement objects nor caller Git variables select source.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM='1',
                       GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    return environment


def git(root, *arguments, environment=None, input=None):
    return subprocess.check_output(
        ['git', '--no-replace-objects', '-C', str(root), *arguments],
        env=git_environment() if environment is None else environment,
        input=input, text=True, stderr=subprocess.PIPE, timeout=180).strip()


def event_identity(environment):
    require(environment.get('GITHUB_EVENT_NAME') == 'push'
            and environment.get('GITHUB_REPOSITORY') == REPOSITORY
            and environment.get('GITHUB_REF') == INTEGRATION_REF,
            'PUSH_EVENT_BOUNDARY')
    expected = environment.get('GITHUB_SHA')
    require(sha(expected), 'PUSH_EVENT_HEAD')
    path = Path(environment['GITHUB_EVENT_PATH'])
    require(path.is_file() and not path.is_symlink(), 'PUSH_EVENT_FILE')
    with path.open('rb') as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    require(len(raw) <= 32 * 1024 * 1024, 'PUSH_EVENT_LIMIT')
    event = load_json(raw)
    require(type(event) is dict and type(event.get('repository')) is dict
            and type(event.get('head_commit')) is dict, 'PUSH_EVENT_OBJECT')
    repository = event['repository']
    require(event.get('ref') == INTEGRATION_REF and event.get('after') == expected
            and event['head_commit'].get('id') == expected and sha(event.get('before'))
            and event['before'] != '0' * 40
            and all(event.get(key) is False for key in ('created', 'deleted', 'forced'))
            and repository.get('full_name') == REPOSITORY
            and repository.get('default_branch') == 'main'
            and type(repository.get('id')) is int and repository['id'] > 0,
            'PUSH_EVENT_BINDING')
    run, attempt = environment.get('GITHUB_RUN_ID'), environment.get('GITHUB_RUN_ATTEMPT')
    require(type(run) is str and run.isdecimal() and int(run) > 0
            and type(attempt) is str and attempt.isdecimal() and int(attempt) > 0,
            'PUSH_RUN_BINDING')
    return {'name': 'push', 'repository': REPOSITORY, 'repository_id': repository['id'],
            'ref': INTEGRATION_REF, 'before': event['before'], 'after': expected,
            'payload_sha256': digest(event), 'run_id': run, 'run_attempt': attempt}


@contextmanager
def isolated_objects(root, head):
    objects = git(root, 'rev-parse', '--path-format=absolute', '--git-path', 'objects')
    require(Path(objects).is_absolute() and '\n' not in objects and '\r' not in objects,
            'PUSH_OBJECT_DIRECTORY')
    with tempfile.TemporaryDirectory(prefix='trnm-push-source-') as temporary:
        bare = Path(temporary) / 'source.git'
        git(Path(temporary), 'init', '--bare', '--quiet', '--object-format=sha1',
            '--template=', str(bare))
        (bare / 'objects/info/alternates').write_text(objects + '\n')
        # This private ref only advertises already-held objects during fetch.
        # No branch or remote ref is created or changed.
        git(bare, 'update-ref', 'refs/source/head', head)
        yield bare


def reproduce(root, head, base=None, receipt=None):
    """Import an actual canonical commit and its new trees/blobs, not just an OID."""
    with isolated_objects(root, head) as bare:
        if base is None:
            git(bare, 'fetch', '--no-tags', '--no-recurse-submodules', REMOTE,
                BASE_REF + ':refs/source/base')
            base = git(bare, 'rev-parse', 'refs/source/base^{commit}')
        else:
            require(sha(base), 'PUSH_BASE_SHA')
            try:
                git(bare, 'cat-file', '-e', base + '^{commit}')
            except subprocess.CalledProcessError:
                # Fetch the already-frozen object; never resolve main again.
                git(bare, 'fetch', '--no-tags', '--no-recurse-submodules', REMOTE,
                    base + ':refs/source/base')
        require(sha(base) and base != head, 'PUSH_DISTINCT_BASE_HEAD')
        if receipt is not None:
            receipt.update(head=head, base_ref=BASE_REF, base=base)
        tree = git(bare, '-c', 'core.attributesFile=' + os.devnull,
                   'merge-tree', '--write-tree', '--no-messages', base, head)
        require(sha(tree), 'PUSH_CANONICAL_TREE')  # Conflicts already fail the Git command.
        if receipt is not None:
            receipt['merge_tree'] = tree
        timestamp = git(bare, 'show', '-s', '--format=%ct', head)
        require(re.fullmatch('[0-9]{1,19}', timestamp) is not None, 'PUSH_COMMIT_TIME')
        environment = git_environment()
        environment.update(GIT_AUTHOR_NAME='Trillionnium CI source',
                           GIT_AUTHOR_EMAIL='ci-source@trillionnium.invalid',
                           GIT_COMMITTER_NAME='Trillionnium CI source',
                           GIT_COMMITTER_EMAIL='ci-source@trillionnium.invalid',
                           GIT_AUTHOR_DATE='@' + timestamp + ' +0000',
                           GIT_COMMITTER_DATE='@' + timestamp + ' +0000')
        merge = git(bare, '-c', 'commit.gpgSign=false', 'commit-tree', tree,
                    '-p', base, '-p', head, environment=environment,
                    input='CI canonical prospective source\n\nbase ' + base + '\nhead ' + head + '\n')
        require(sha(merge), 'PUSH_MERGE_SHA')
        if receipt is not None:
            receipt['merge'] = merge
        # The original verifier's temporary merge repository does not export its
        # new tree objects. Import the real closure before deleting this owner.
        git(root, '-c', 'protocol.file.allow=always', 'fetch', '--no-tags',
            '--no-recurse-submodules', '--no-write-fetch-head', str(bare), merge)
    require(git(root, 'show', '-s', '--format=%P', merge).split() == [base, head]
            and tree == _canonical_merge_tree(root, base, head), 'PUSH_CANONICAL_MERGE')
    return base, tree, merge


def resolve(root=ROOT, environment=None, receipt=None):
    environment = os.environ if environment is None else environment
    event = event_identity(environment)
    head = event['after']
    if receipt is not None:
        receipt.update(event=event, head=head)
    before = verify('head', head, root=root)
    if receipt is not None:
        receipt['source_head'] = before
    base, tree, merge = reproduce(root, head, receipt=receipt)
    require(verify('head', head, root=root) == before, 'PUSH_RESOLVER_SOURCE_CHANGED')
    return {'schema': SCHEMA, 'event': event, 'head': head, 'base_ref': BASE_REF,
            'base': base, 'merge': merge, 'merge_tree': tree, 'merge_format': MERGE_FORMAT,
            'source_head': before, 'git_version': git(root, '--version'),
            'resolved_utc': datetime.now(timezone.utc).isoformat(),
            'is_github_pr_merge': False, 'production_activation': False}


def materialize(context, expected_digest, kind, root=ROOT, environment=None):
    environment = os.environ if environment is None else environment
    require(type(context) is dict and set(context) == {
        'schema', 'event', 'head', 'base_ref', 'base', 'merge', 'merge_tree', 'merge_format',
        'source_head', 'git_version', 'resolved_utc', 'is_github_pr_merge', 'production_activation'},
        'PUSH_CONTEXT_SHAPE')
    require(type(expected_digest) is str and re.fullmatch('[0-9a-f]{64}', expected_digest)
            and digest(context) == expected_digest, 'PUSH_CONTEXT_DIGEST')
    event = event_identity(environment)
    require(context['schema'] == SCHEMA and context['event'] == event
            and context['head'] == event['after'] and context['base_ref'] == BASE_REF
            and context['merge_format'] == MERGE_FORMAT
            and context['is_github_pr_merge'] is False and context['production_activation'] is False
            and all(sha(context[key]) for key in ('head', 'base', 'merge', 'merge_tree')),
            'PUSH_CONTEXT_BINDING')
    require(all(context[key] == environment.get('EXPECTED_' + key.upper())
                for key in ('head', 'base', 'merge')), 'PUSH_EXPECTED_CONTEXT')
    require(kind in ('head', 'prospective-merge'), 'PUSH_SOURCE_KIND')
    require(verify('head', context['head'], root=root) == context['source_head'],
            'PUSH_CHECKOUT_SOURCE')
    base, tree, merge = reproduce(root, context['head'], context['base'])
    require((base, tree, merge) == (context['base'], context['merge_tree'], context['merge']),
            'PUSH_REPRODUCED_SOURCE')
    selected = context['head'] if kind == 'head' else merge
    git(root, '-c', 'core.hooksPath=' + os.devnull, 'checkout', '--detach', selected)
    actual = verify(kind, context['head'],
                    base if kind == 'prospective-merge' else None,
                    merge if kind == 'prospective-merge' else None, root=root)
    return {'schema': 'trnm-integration-push-materialization-v1',
            'context': context, 'context_sha256': expected_digest, 'source': actual,
            'github_event_name': environment['GITHUB_EVENT_NAME'],
            'github_sha': environment['GITHUB_SHA'], 'is_github_pr_merge': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('resolve', 'materialize'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--context-json')
    parser.add_argument('--context-sha256')
    parser.add_argument('--kind', choices=('head', 'prospective-merge'))
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.resolve().is_relative_to(ROOT),
            'PUSH_OUTPUT_OUTSIDE_SOURCE')
    result = {'schema': 'trnm-integration-push-source-failure-v1', 'mode': args.mode,
              'completed': False, 'is_github_pr_merge': False,
              'workflow_inputs': {key: os.environ.get(key) for key in (
                  'GITHUB_EVENT_NAME', 'GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_SHA',
                  'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB',
                  'EXPECTED_HEAD', 'EXPECTED_BASE', 'EXPECTED_MERGE')}}
    try:
        if args.mode == 'resolve':
            require(args.context_json is None and args.context_sha256 is None and args.kind is None,
                    'PUSH_RESOLVE_ARGUMENTS')
            result = resolve(receipt=result)
            context_digest = digest(result)
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
                for key in ('head', 'base', 'merge'):
                    stream.write(key + '=' + result[key] + '\n')
                stream.write('context=' + canonical(result) + '\ncontext_sha256=' + context_digest + '\n')
        else:
            require(args.context_json is not None and len(args.context_json.encode()) <= CONTEXT_LIMIT,
                    'PUSH_CONTEXT_LIMIT')
            result.update(attempted_context_json=args.context_json, context_sha256=args.context_sha256,
                          source_kind=args.kind)
            context = load_json(args.context_json)
            result.update(attempted_context=context, context_sha256=args.context_sha256,
                          source_kind=args.kind, github_event_name=os.environ.get('GITHUB_EVENT_NAME'),
                          github_sha=os.environ.get('GITHUB_SHA'))
            result = materialize(context, args.context_sha256, args.kind)
        print(canonical(result))
    except BaseException as error:
        result['failure_type'] = type(error).__name__
        result['error'] = str(error)[:2048]
        if isinstance(error, subprocess.CalledProcessError):
            result['git_stdout'] = (error.output or '')[:65536]
            result['git_stderr'] = (error.stderr or '')[:65536]
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write('\n')


if __name__ == '__main__':
    main()
