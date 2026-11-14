#!/usr/bin/env python3
"""Commit the exact reviewed metadata tree and verify it; never push."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

REPO = Path('/home/qian-qi/work/chain-bt-4a0b-publication02')
CONTROL = Path('/home/qian-qi/chain-bt-owner-convergence-20261112-4a0b-publication-control')
PARENT = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
BRANCH = 'fix/chain-bt-owner-convergence-20261112-4a0b'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(['/usr/bin/git', *args], cwd=REPO, text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-report', type=Path, required=True)
    parser.add_argument('--stage-sha256', required=True)
    parser.add_argument('--output-name', required=True)
    args = parser.parse_args()
    require(args.stage_report.is_relative_to(CONTROL), 'stage report outside task control')
    raw_stage = args.stage_report.read_bytes()
    require(sha(raw_stage) == args.stage_sha256, 'reviewed stage receipt changed')
    stage = json.loads(raw_stage)
    require(stage['schema'] == 'trnm.bt-documentation-publication-stage.v1' and
            stage['source'] == PARENT and stage['completed'] is True and
            stage['passed'] is True and stage['committed'] is False and stage['pushed'] is False,
            'stage did not pass')
    require(stage['git_index_staged'] is True and
            stage['staged_tree'] == stage['validation_tree_before'], 'staged tree changed')
    output = CONTROL / args.output_name
    require(output.parent == CONTROL and not output.exists(), 'fresh commit observation required')
    output.mkdir(mode=0o700)
    control_fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(control_fd)
    finally:
        os.close(control_fd)
    report = {'schema': 'trnm.bt-documentation-publication-commit.v1',
              'runtime_source': PARENT, 'reviewed_staged_tree': stage['staged_tree'],
              'stage_report_sha256': args.stage_sha256, 'completed': False,
              'passed': False, 'committed': False, 'commit_attempted': False,
              'commit_effect_state': 'not_attempted', 'pushed': False, 'commands': [],
              'started_unix_ns': time.time_ns()}

    def save() -> None:
        pending = output / 'report.pending.json'
        with pending.open('w') as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, output / 'report.json')
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def run(name: str, argv: list[str], timeout: int = 600) -> None:
        item = {'name': name, 'argv': argv, 'status': 'running'}
        report['commands'].append(item)
        save()
        start = time.monotonic_ns()
        timed_out = False
        code = None
        try:
            with (output / (name + '.stdout')).open('xb') as stdout, \
                 (output / (name + '.stderr')).open('xb') as stderr:
                result = subprocess.run(argv, cwd=REPO, stdout=stdout, stderr=stderr,
                                        timeout=timeout,
                                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                code = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            item.update({'status': 'completed', 'exit_code': code, 'timed_out': timed_out,
                         'elapsed_ns': time.monotonic_ns() - start})
            for stream in ('stdout', 'stderr'):
                data = (output / (name + '.' + stream)).read_bytes()
                item[stream + '_bytes'] = len(data)
                item[stream + '_sha256'] = sha(data)
            save()
        require(code == 0 and not timed_out, 'commit observation command failed: ' + name)

    save()
    try:
        require(git('rev-parse', 'HEAD') == PARENT and git('branch', '--show-current') == BRANCH and
                git('remote', 'get-url', 'origin') == ORIGIN, 'publication repository identity')
        require(git('write-tree') == stage['staged_tree'], 'Git index changed after stage review')
        require(not git('diff', '--name-only') and
                not git('ls-files', '--others', '--exclude-standard'), 'unreviewed worktree change')
        require(set(git('diff', '--cached', '--name-only', PARENT).splitlines()) ==
                set(stage['changed_paths']), 'reviewed staged scope changed')
        for pin in stage['file_pins']:
            data = (REPO / pin['path']).read_bytes()
            require(len(data) == pin['bytes'] and sha(data) == pin['sha256'],
                    'reviewed staged file changed: ' + pin['path'])
        run('preflight-before-commit', ['/bin/bash', 'scripts/project-preflight.sh'])
        run('preflight-staged', ['/bin/bash', 'scripts/project-preflight.sh', '--staged'])
        message = (
            'docs(cell): record frozen BT owner convergence validation\n\n'
            'Bind complete model/environment selection and native M12/CGJ3 research\n'
            'to the exact frozen runtime and separately identified observations.\n'
            'Retain original failures, recovered evidence gaps, runtime dependencies\n'
            'and false qualification flags. Keep runtime and validation code unchanged.\n'
        )
        message_path = output / 'commit-message.txt'
        with message_path.open('x') as stream:
            stream.write(message)
        report['commit_attempted'] = True
        report['committed'] = None
        report['commit_effect_state'] = 'attempt_in_progress'
        save()
        run('commit-reviewed-metadata', ['/usr/bin/git', '-c', 'user.name=Codex',
                                        '-c', 'user.email=codex@openai.com', 'commit',
                                        '--signoff', '--file', str(message_path)])
        commit = git('rev-parse', 'HEAD')
        report['committed'] = True
        report['commit_effect_state'] = 'confirmed_created'
        report['publication_commit'] = commit
        require(commit != PARENT and git('rev-parse', 'HEAD^') == PARENT and
                git('rev-parse', 'HEAD^{tree}') == stage['staged_tree'],
                'committed object differs from reviewed tree/parent')
        require(not git('status', '--porcelain=v1', '--untracked-files=all'),
                'worktree not clean after commit')
        require(set(git('diff', '--name-only', PARENT, commit).splitlines()) ==
                set(stage['changed_paths']), 'committed scope changed')
        report['runtime_subtrees_unchanged'] = {}
        for name, tree in stage['runtime_subtrees_unchanged'].items():
            require(git('rev-parse', commit + ':' + name) == tree, 'runtime subtree changed: ' + name)
            report['runtime_subtrees_unchanged'][name] = tree
        run('preflight-committed', ['/bin/bash', 'scripts/project-preflight.sh'])
        for name in ('check_repository', 'test_ci_source_integrity',
                     'check_pq_research_integration', 'test_pq_research_integration',
                     'test_pq_authority_effect_register'):
            run(name, ['/usr/bin/python3', '-B', 'scripts/ci/' + name + '.py'])
        run('inventory', ['/usr/bin/python3', '-B', 'scripts/refresh_distributed_source_inventory.py', '--check'])
        run('source-after', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                             '--kind', 'head', '--expected-head', commit])
        require(git('rev-parse', 'HEAD') == commit and
                not git('status', '--porcelain=v1', '--untracked-files=all'),
                'committed source changed during validation')
        report['final_identity'] = {'head': commit, 'tree': stage['staged_tree'],
                                    'branch': BRANCH, 'status': ''}
        report['passed'] = True
    except BaseException as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
        raise
    finally:
        # A lost/failed command acknowledgement cannot establish that Git had
        # no effect. Observe refs only; never retry commit, reset, or push here.
        if report['commit_attempted']:
            try:
                observed_head = git('rev-parse', 'HEAD')
                observed_tree = git('rev-parse', 'HEAD^{tree}')
                observed_parent = git('rev-parse', 'HEAD^')
                report['commit_effect_reconciliation'] = {
                    'head': observed_head, 'tree': observed_tree,
                    'parent': observed_parent, 'observed_unix_ns': time.time_ns()}
                if (observed_head != PARENT and observed_parent == PARENT and
                        observed_tree == stage['staged_tree']):
                    report['committed'] = True
                    report['publication_commit'] = observed_head
                    report['commit_effect_state'] = 'confirmed_created'
                else:
                    report['committed'] = None
                    report['commit_effect_state'] = (
                        'effect_unresolved_head_still_parent' if observed_head == PARENT
                        else 'effect_unresolved_unexpected_head')
                    report['passed'] = False
            except BaseException as reconciliation_error:
                report['committed'] = None
                report['commit_effect_state'] = 'effect_unknown_readback_failed'
                report['commit_effect_reconciliation_error'] = (
                    type(reconciliation_error).__name__ + ': ' + str(reconciliation_error))
                report['passed'] = False
        report['completed'] = True
        report['finished_unix_ns'] = time.time_ns()
        save()
        raw = (output / 'report.json').read_bytes()
        print(json.dumps({'completed': True, 'passed': report['passed'],
                          'committed': report['committed'], 'pushed': False,
                          'commit_effect_state': report['commit_effect_state'],
                          'publication_commit': report.get('publication_commit'),
                          'report': str(output / 'report.json'),
                          'bytes': len(raw), 'sha256': sha(raw)}), flush=True)
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
