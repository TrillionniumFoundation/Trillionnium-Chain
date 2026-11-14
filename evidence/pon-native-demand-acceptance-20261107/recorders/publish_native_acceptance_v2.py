#!/usr/bin/env python3
"""Normal Git fast-forward and existing draft PR update through the local H channel."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
SOURCE = ROOT / 'chain-publication'
REPO = 'TrillionniumFoundation/Trillionnium-Chain'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
BRANCH = 'fix/chain-native-demand-acceptance-20261107'
BASE = 'fix/chain-demand-evaluation-20261107'
OLD = '690f710c1b6808787996e86aa4c36bd53e1f3939'
ARCHIVE = 'evidence/pon-native-demand-acceptance-20261107'
GIT_AUTH = ['/usr/bin/git', '-c', 'credential.helper=', '-c', 'credential.helper=!/usr/bin/gh auth git-credential']

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--gates-directory', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.expected_head) or not re.fullmatch(r'[a-z0-9-]+', args.gates_directory):
        raise RuntimeError('Invalid publication identity')
    out = ROOT / 'native-acceptance-publication-v2'
    out.mkdir()
    commands = []
    def command(argv, label, stdin=None):
        proc = subprocess.run(argv, cwd=SOURCE, input=stdin, capture_output=True, check=False)
        (out / (label + '.stdout.log')).write_bytes(proc.stdout)
        (out / (label + '.stderr.log')).write_bytes(proc.stderr)
        row = {'command': argv, 'exit_code': proc.returncode, 'stdout_sha256': sha(proc.stdout), 'stderr_sha256': sha(proc.stderr)}
        commands.append(row)
        save(out / (label + '.json'), row)
        if proc.returncode != 0:
            raise RuntimeError('Publication command failed; reconcile before retry: ' + label)
        return proc.stdout
    def git(*argv):
        return subprocess.check_output(['/usr/bin/git', *argv], cwd=SOURCE).decode().strip()
    head = git('rev-parse', 'HEAD')
    tree = git('rev-parse', 'HEAD^{tree}')
    if head != args.expected_head or git('branch', '--show-current') != BRANCH or git('remote', 'get-url', 'origin') != ORIGIN:
        raise RuntimeError('Unexpected source/ref/repository')
    if git('remote', 'get-url', '--push', '--all', 'origin').splitlines() != [ORIGIN]:
        raise RuntimeError('Unexpected origin push URL')
    if git('status', '--porcelain=v1', '--untracked-files=all'):
        raise RuntimeError('Dirty publication worktree')
    changed = git('diff', '--name-only', OLD, head).splitlines()
    if any(p != 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md' and not p.startswith(ARCHIVE + '/') for p in changed):
        raise RuntimeError('Publication changes runtime implementation')
    gates_path = ROOT / args.gates_directory / 'summary.json'
    gates_raw = gates_path.read_bytes()
    gates = json.loads(gates_raw)
    if gates['head'] != head or gates['all_selected_gates_passed'] is not True or gates['source_unchanged'] is not True or gates['source_before_sha256'] != gates['source_after_sha256']:
        raise RuntimeError('Exact publication-tree gates not accepted')
    body = ROOT / 'PR_BODY_NATIVE_ACCEPTANCE.md'
    body_raw = body.read_bytes()
    if b'{{' in body_raw or head.encode() not in body_raw:
        raise RuntimeError('PR body incomplete or unbound')
    command(['bash', 'scripts/project-preflight.sh'], 'preflight-dev')
    before = json.loads(command(['/usr/bin/gh', 'pr', 'view', '779', '--repo', REPO, '--json', 'number,url,state,isDraft,baseRefName,headRefName,headRefOid'], 'pr-before'))
    if before['state'] != 'OPEN' or before['isDraft'] is not True or before['baseRefName'] != BASE or before['headRefName'] != BRANCH or before['headRefOid'] != OLD:
        raise RuntimeError('Existing PR changed; preserve and inspect')
    remote = command([*GIT_AUTH, 'ls-remote', '--heads', 'origin', 'refs/heads/' + BRANCH], 'remote-before').decode().strip()
    if remote != OLD + '\trefs/heads/' + BRANCH:
        raise RuntimeError('Remote branch changed; preserve and inspect')
    command(['/usr/bin/git', 'merge-base', '--is-ancestor', OLD, head], 'fast-forward-ancestry')
    update = f'refs/heads/{BRANCH} {head} refs/heads/{BRANCH} {OLD}\n'.encode()
    command(['bash', 'scripts/project-preflight.sh', '--push', 'origin', ORIGIN], 'preflight-push', stdin=update)
    if git('rev-parse', 'HEAD') != head or git('rev-parse', 'HEAD^{tree}') != tree or git('status', '--porcelain=v1', '--untracked-files=all') or git('remote', 'get-url', '--push', '--all', 'origin').splitlines() != [ORIGIN]:
        raise RuntimeError('Publication state changed immediately before push')
    command([*GIT_AUTH, 'push', 'origin', head + ':refs/heads/' + BRANCH], 'push')
    remote_after = command([*GIT_AUTH, 'ls-remote', '--heads', 'origin', 'refs/heads/' + BRANCH], 'remote-after').decode().strip()
    if remote_after != head + '\trefs/heads/' + BRANCH:
        raise RuntimeError('Remote head readback mismatch')
    command(['/usr/bin/gh', 'pr', 'edit', '779', '--repo', REPO, '--body-file', str(body)], 'pr-edit')
    after = json.loads(command(['/usr/bin/gh', 'pr', 'view', '779', '--repo', REPO, '--json', 'number,url,state,isDraft,baseRefName,headRefName,headRefOid,body'], 'pr-after'))
    if after['headRefOid'] != head or after['baseRefName'] != BASE or after['headRefName'] != BRANCH or after['state'] != 'OPEN' or after['isDraft'] is not True or after['body'].rstrip() != body_raw.decode().rstrip():
        raise RuntimeError('Draft PR readback mismatch')
    commit = json.loads(command(['/usr/bin/gh', 'api', f'repos/{REPO}/git/commits/{head}'], 'remote-commit'))
    if commit['sha'] != head or commit['tree']['sha'] != tree:
        raise RuntimeError('Remote commit/tree readback mismatch')
    remote_index = command(['/usr/bin/gh', 'api', f'repos/{REPO}/contents/{ARCHIVE}/ARTIFACT_INDEX.json?ref={head}', '-H', 'Accept: application/vnd.github.raw+json'], 'remote-artifact-index')
    if remote_index != (SOURCE / ARCHIVE / 'ARTIFACT_INDEX.json').read_bytes():
        raise RuntimeError('Remote artifact index readback mismatch')
    receipt = {'schema': 'pon-native-acceptance-local-github-publication-v1', 'result': 'PUSHED_AND_REMOTE_VERIFIED', 'published_unix_seconds': time.time(), 'implementation_source': OLD, 'publication_head': head, 'publication_tree': tree, 'branch': BRANCH, 'base': BASE, 'pull_request': {k: v for k, v in after.items() if k != 'body'}, 'exact_publication_gates': {'path': str(gates_path), 'sha256': sha(gates_raw)}, 'artifact_index_sha256': sha(remote_index), 'body_sha256': sha(body_raw), 'commands': commands, 'force_push': False, 'merge': False, 'production_activation': False}
    save(out / 'result.json', receipt)
    print(json.dumps({'result': receipt['result'], 'head': head, 'tree': tree, 'pull_request': after['url'], 'isDraft': after['isDraft']}), flush=True)

if __name__ == '__main__':
    main()
