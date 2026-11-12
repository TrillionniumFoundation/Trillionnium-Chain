#!/usr/bin/env python3
"""Publish one verified descendant to the existing draft PR, preserving history."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

REPO = Path('/home/qian-qi/work/chain-bt-4a0b-publication02')
CONTROL = Path('/home/qian-qi/chain-bt-owner-convergence-20261112-4a0b-publication-control')
RUNTIME = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
OLD_HEAD = '040fb0cf460a6db568f0b4ec5ba581add3f2d2ba'
BASE = '30ce6e99c5d0d86e6563a49786e8b1e41b44c6c6'
LOCAL_BRANCH = 'fix/chain-bt-owner-convergence-20261112-4a0b'
REMOTE_BRANCH = 'fix/chain-cell-storage-four-gates-20261111-2bfb'
BASE_BRANCH = 'fix/chain-cell-paged-release-34e09-20261110'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
SLUG = 'TrillionniumFoundation/Trillionnium-Chain'
ORIGINAL_BODY_SHA = '8f67f6a91d76f1bc0104e32d3c08d76a1368935d4bb1393ed77fc4402b93a6cb'
GH = '/usr/bin/gh'
GIT_AUTH = ['/usr/bin/git', '-c', 'credential.helper=', '-c',
            'credential.https://github.com.helper=!/usr/bin/gh auth git-credential']


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular(path: Path, maximum: int = 4 * 1024 * 1024) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                'bounded regular file required: ' + str(path))
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(len(raw) == before.st_size and
            tuple(getattr(before, k) for k in fields) == tuple(getattr(after, k) for k in fields),
            'file changed while reading: ' + str(path))
    return raw


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit-report', type=Path, required=True)
    parser.add_argument('--commit-report-sha256', required=True)
    parser.add_argument('--body-file', type=Path, required=True)
    parser.add_argument('--body-sha256', required=True)
    parser.add_argument('--output-name', required=True)
    args = parser.parse_args()
    require(args.commit_report.is_relative_to(CONTROL) and args.body_file.parent == CONTROL,
            'reviewed inputs outside task control')
    commit_raw = regular(args.commit_report)
    require(sha(commit_raw) == args.commit_report_sha256, 'commit review receipt changed')
    committed = json.loads(commit_raw)
    require(committed['schema'] == 'trnm.bt-documentation-publication-commit.v1' and
            committed['completed'] is True and committed['passed'] is True and
            committed['committed'] is True and committed['pushed'] is False and
            committed['commit_effect_state'] == 'confirmed_created' and
            committed['runtime_source'] == RUNTIME, 'publication commit is not verified')
    commit = committed['publication_commit']
    require(len(commit) == 40 and all(c in '0123456789abcdef' for c in commit), 'commit identity')
    body_raw = regular(args.body_file, 65536)
    require(sha(body_raw) == args.body_sha256, 'reviewed PR description changed')
    body = body_raw.decode('utf-8')
    require(commit in body and RUNTIME in body and 'HOLD' in body,
            'PR description lacks exact source and qualification scope')
    output = CONTROL / args.output_name
    require(output.parent == CONTROL and not output.exists(), 'fresh publication output required')
    output.mkdir(mode=0o700)
    fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    environment = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
                   'GH_PROMPT_DISABLED': '1', 'GH_HOST': 'github.com',
                   'PYTHONDONTWRITEBYTECODE': '1'}
    for name in tuple(environment):
        if name.startswith('GIT_TRACE') or name in ('GIT_CURL_VERBOSE', 'GH_DEBUG'):
            environment.pop(name)
    report = {'schema': 'trnm.bt-existing-draft-pr-publication.v1',
              'runtime_source': RUNTIME, 'publication_commit': commit,
              'expected_remote_predecessor': OLD_HEAD, 'expected_base': BASE,
              'commit_report_sha256': args.commit_report_sha256,
              'reviewed_body_sha256': args.body_sha256,
              'started_unix_ns': time.time_ns(), 'completed': False, 'passed': False,
              'push_attempted': False, 'pushed': False, 'push_effect': 'not_attempted',
              'body_update_attempted': False, 'body_updated': False,
              'body_effect': 'not_attempted', 'forced': False, 'merged': False,
              'production_activation': False, 'commands': []}

    def save() -> None:
        pending = output / 'report.pending.json'
        with pending.open('w') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, output / 'report.json')
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def run(name: str, argv: list[str], stdin: bytes | None = None, timeout: int = 300) -> bytes:
        item = {'name': name, 'argv': argv, 'status': 'running'}
        if stdin is not None:
            item['stdin_bytes'] = len(stdin); item['stdin_sha256'] = sha(stdin)
        report['commands'].append(item); save()
        code = None; timed_out = False; started = time.monotonic_ns()
        try:
            with (output / (name + '.stdout')).open('xb') as stdout, \
                    (output / (name + '.stderr')).open('xb') as stderr:
                result = subprocess.run(argv, cwd=REPO, env=environment, input=stdin,
                                        stdout=stdout, stderr=stderr, timeout=timeout)
                code = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            item.update(status='completed', exit_code=code, timed_out=timed_out,
                        elapsed_ns=time.monotonic_ns() - started)
            for stream in ('stdout', 'stderr'):
                raw = (output / (name + '.' + stream)).read_bytes()
                item[stream + '_bytes'] = len(raw); item[stream + '_sha256'] = sha(raw)
            save()
        require(code == 0 and not timed_out, 'publication command failed: ' + name)
        return (output / (name + '.stdout')).read_bytes()

    def git(*argv: str) -> str:
        return subprocess.check_output(['/usr/bin/git', *argv], cwd=REPO,
                                       env=environment, text=True).strip()

    def remote(name: str) -> str:
        raw = run(name, GIT_AUTH + ['ls-remote', 'origin', 'refs/heads/' + REMOTE_BRANCH])
        rows = raw.decode().strip().splitlines()
        require(len(rows) == 1 and rows[0].split()[1] == 'refs/heads/' + REMOTE_BRANCH,
                'remote branch identity')
        return rows[0].split()[0]

    def pull(name: str) -> dict:
        query = '{number,state,draft,head_sha:.head.sha,head_ref:.head.ref,base_sha:.base.sha,base_ref:.base.ref,body}'
        value = json.loads(run(name, [GH, 'api', 'repos/' + SLUG + '/pulls/923', '--jq', query]))
        require(value['number'] == 923 and value['state'] == 'open' and value['draft'] is True and
                value['head_ref'] == REMOTE_BRANCH and value['base_ref'] == BASE_BRANCH and
                value['base_sha'] == BASE, 'PR scope changed')
        return value

    save()
    try:
        require(git('rev-parse', 'HEAD') == commit and git('rev-parse', 'HEAD^') == RUNTIME and
                git('rev-parse', 'HEAD^{tree}') == committed['reviewed_staged_tree'] and
                git('branch', '--show-current') == LOCAL_BRANCH and
                git('remote', 'get-url', 'origin') == ORIGIN and
                not git('status', '--porcelain=v1', '--untracked-files=all'), 'local publication identity')
        for name, tree in committed['runtime_subtrees_unchanged'].items():
            require(git('rev-parse', commit + ':' + name) == tree == git('rev-parse', RUNTIME + ':' + name),
                    'runtime subtree changed: ' + name)
        actor = run('administrator-before-push', [GH, 'api', 'user', '--jq', '.login']).decode().strip()
        require(actor == 'ProfHepta', 'administrator ProfHepta required')
        report['actor'] = actor
        prior = pull('pr-before-push')
        require(prior['head_sha'] == OLD_HEAD and remote('remote-before-push') == OLD_HEAD,
                'concurrent remote changes must be reconciled before push')
        require(sha(prior['body'].encode()) == ORIGINAL_BODY_SHA and
                body.endswith(prior['body']), 'original PR description changed or not preserved')
        run('preflight-before-push', ['/bin/bash', 'scripts/project-preflight.sh'])
        run('physical-source-before-push', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                                            '--kind', 'head', '--expected-head', commit])
        boundary = ('refs/heads/' + LOCAL_BRANCH + ' ' + commit + ' refs/heads/' +
                    REMOTE_BRANCH + ' ' + OLD_HEAD + '\n').encode()
        run('original-push-boundary', ['/usr/bin/python3', '-B', 'scripts/ci/project_boundary.py',
                                       '--push', 'origin', ORIGIN], stdin=boundary)
        push_urls = git('remote', 'get-url', '--push', '--all', 'origin').splitlines()
        require(push_urls == [ORIGIN], 'effective push URL must be the single canonical HTTPS repository')
        report['effective_push_urls'] = push_urls
        report.update(push_attempted=True, pushed=None, push_effect='attempt_in_progress'); save()
        run('ordinary-push', GIT_AUTH + ['push', 'origin', commit + ':refs/heads/' + REMOTE_BRANCH], timeout=600)
        require(remote('remote-after-push') == commit, 'push readback differs')
        current = pull('pr-after-push')
        require(current['head_sha'] == commit, 'PR head did not reach reviewed publication')
        report.update(pushed=True, push_effect='confirmed_published'); save()
        require(sha(current['body'].encode()) == ORIGINAL_BODY_SHA,
                'concurrent PR description change must be preserved before editing')
        require(sha(regular(args.body_file, 65536)) == args.body_sha256, 'description file changed')
        actor_after = run('administrator-before-description', [GH, 'api', 'user', '--jq', '.login']).decode().strip()
        require(actor_after == 'ProfHepta', 'administrator changed before PR metadata update')
        report.update(body_update_attempted=True, body_updated=None, body_effect='attempt_in_progress'); save()
        run('update-pr-description', [GH, 'pr', 'edit', '923', '--repo', SLUG,
                                      '--body-file', '-'], stdin=body_raw)
        after = pull('pr-after-description')
        require(after['head_sha'] == commit and sha(after['body'].encode()) == args.body_sha256,
                'description update readback differs')
        report.update(body_updated=True, body_effect='confirmed_updated')
        require(git('rev-parse', 'HEAD') == commit and
                not git('status', '--porcelain=v1', '--untracked-files=all'), 'local source changed')
        report['passed'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__; report['error'] = str(error)
    finally:
        # Reads only after an uncertain acknowledgement: never repeat either write.
        if report['push_attempted']:
            try:
                actual_remote = remote('remote-final-reconciliation')
                actual_pr = pull('pr-final-reconciliation')
                report['final_remote_head'] = actual_remote
                report['final_pr'] = {k: v for k, v in actual_pr.items() if k != 'body'}
                report['final_body_sha256'] = sha(actual_pr['body'].encode())
                if actual_remote == commit and actual_pr['head_sha'] == commit:
                    report.update(pushed=True, push_effect='confirmed_published')
                else:
                    report.update(pushed=None, push_effect='effect_unresolved', passed=False)
                if report['body_update_attempted']:
                    if report['final_body_sha256'] == args.body_sha256:
                        report.update(body_updated=True, body_effect='confirmed_updated')
                    else:
                        report.update(body_updated=None, body_effect='effect_unresolved', passed=False)
            except BaseException as error:
                report['effect_reconciliation_error'] = type(error).__name__ + ': ' + str(error)
                report['passed'] = False
                if report['pushed'] is not True:
                    report.update(pushed=None, push_effect='effect_unknown_readback_failed')
                if report['body_update_attempted'] and report['body_updated'] is not True:
                    report.update(body_updated=None, body_effect='effect_unknown_readback_failed')
        report['completed'] = True; report['finished_unix_ns'] = time.time_ns(); save()
        raw = (output / 'report.json').read_bytes()
        print(json.dumps({'completed': True, 'passed': report['passed'],
                          'pushed': report['pushed'], 'body_updated': report['body_updated'],
                          'publication_commit': commit, 'report': str(output / 'report.json'),
                          'bytes': len(raw), 'sha256': sha(raw)}, sort_keys=True), flush=True)
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
