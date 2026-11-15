#!/usr/bin/env python3
"""Preserve a completed authority run, merge the reviewed concurrent PQ base.

One-shot, exact-source integration. All subprocess output is retained. This
does not push, activate a profile, or alter deployed services or keys.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

TASK = Path('/home/qian-qi/work/chain-pq-authority-20261108-9d315')
REPO = TASK / 'repo'
OUT = TASK / 'validation/concurrent-base-integration-01'
PREP = Path(__file__).resolve().parent
EVIDENCE = REPO / 'evidence/pq-authority-preflight-20261108-9d315'
BASE = '12e510b211110d93d9ead07e02c07a1eecc28ae9'
OURS = '62ed4e4facae4e0eb9f3fdeb82001acb3b21be47'
THEIRS = '8d8f05566b2a1612a3bf4a6c6c71635df454d397'
BRANCH = 'fix/chain-pq-authority-preflight-20261108-9d315'
BASE_BRANCH = 'fix/chain-pq-integrated-20261105-df8969'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
EVIDENCE_REL = EVIDENCE.relative_to(REPO).as_posix()
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
REPORT = 'docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md'
RUNNER_REL = EVIDENCE_REL + '/authority-integrated-validation-runner.py'
MERGED_SHA256 = {
    CORPUS: '300b1dc6bda1304897e5157e8abe8d5518a0e8ff4a64183cdccebd4149284b10',
    'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md':
        'f418f72da2590f5442458331251df37823344d9b8d6bf4abb5e38dfd5582ca53',
    'scripts/ci/check_ci_contract.py':
        '91dd4ee857079588bbedb005c469d6569769908f1c606c2abb150cc7e1665843',
    'scripts/ci/test_ci_contract.py':
        'da6629f3cc54e501c77141f94670e424194b625951fc742fd3c987df6b0094a9',
}
ENV = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1',
           PYTHONDONTWRITEBYTECODE='1')
commands = []

def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(REPO), *args], env=ENV)

def run(label, argv, allowed=(0,), stdin=None):
    start = time.monotonic()
    result = subprocess.run(argv, cwd=REPO, env=ENV, input=stdin, capture_output=True)
    records = {}
    for suffix, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
        path = OUT / (label + '.' + suffix + '.log')
        path.write_bytes(data)
        records[path.name] = {'bytes': len(data), 'sha256': digest(data)}
    row = {'label': label, 'argv': argv, 'exit_code': result.returncode,
           'elapsed_seconds': time.monotonic() - start, 'logs': records}
    commands.append(row)
    save(OUT / 'commands.json', commands)
    print(json.dumps({'step': label, 'exit_code': result.returncode}), flush=True)
    if result.returncode not in allowed:
        raise RuntimeError('command failed: ' + label)
    return result

def checked_copy_tree(source, destination):
    if destination.exists():
        raise ValueError('destination already exists: ' + str(destination))
    for path in source.rglob('*'):
        st = path.lstat()
        if not (stat.S_ISDIR(st.st_mode) or (stat.S_ISREG(st.st_mode) and st.st_nlink == 1)):
            raise ValueError('nonregular retained input: ' + str(path))
    shutil.copytree(source, destination)
    records = {}
    for path in sorted(source.rglob('*')):
        if path.is_file():
            relative = path.relative_to(source)
            data = path.read_bytes()
            assert data == (destination / relative).read_bytes()
            records[relative.as_posix()] = {'bytes': len(data), 'sha256': digest(data)}
    return records

def rebuild_index():
    path = EVIDENCE / 'artifact-index.json'
    index = json.loads(path.read_text())
    index['concurrent_base_commit'] = THEIRS
    index['validated_commits'] = [{'commit': OURS,
        'tree': '38a1d4da1a6dc8c93d49ca181c8e35ecb79ef776',
        'directory': 'committed-source-01', 'command_gates': 28}]
    index['files'] = {}
    for item in sorted(EVIDENCE.rglob('*')):
        if item.is_dir():
            continue
        relative = item.relative_to(EVIDENCE).as_posix()
        if relative == 'artifact-index.json':
            continue
        if re.fullmatch(r'\.hepta-lock-[0-9a-f]{24}', item.name):
            raise ValueError('tool lock remains in evidence tree')
        st = item.lstat()
        assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
        data = item.read_bytes()
        index['files'][relative] = {'bytes': len(data), 'sha256': digest(data)}
    save(path, index)
    return index

def main():
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(Path(__file__).resolve(), OUT / 'driver.py')
    for name, expected in [
        ('overlap.patch', '9159743906948f11cd811805d3294385349677f0b752136313d58a2beea102b7'),
        ('authority-integrated-validation-runner.py', 'f5fc66625c09cfccf5054ec705a49c2a88f234c0620e6e6426aa4b7efcb71b86'),
    ]:
        data = (PREP / name).read_bytes()
        assert digest(data) == expected
        (OUT / name).write_bytes(data)
    original = TASK / 'validation/committed-source-01'
    summary = json.loads((original / 'summary.json').read_text())
    assert summary['result'] == 'PASS' and not summary['failures']
    assert summary['expected_head'] == OURS
    assert summary['source_unchanged'] and summary['provider_unchanged']
    assert len(summary['commands']) == 28 and all(r['passed'] for r in summary['commands'])
    assert json.loads((original / 'sqlite-qualification.json').read_text())['passed']
    assert git('rev-parse', 'HEAD').decode().strip() == OURS
    assert git('branch', '--show-current').decode().strip() == BRANCH
    assert git('remote', 'get-url', 'origin').decode().strip() == ORIGIN
    assert not git('status', '--porcelain=v1', '--untracked-files=all').strip()
    run('preflight', ['/bin/bash', 'scripts/project-preflight.sh'])
    fetch = ['/usr/bin/git', '-c', 'credential.helper=', '-c',
             'credential.helper=!/usr/bin/gh auth git-credential', 'fetch', '--no-tags',
             'origin', 'refs/heads/' + BASE_BRANCH + ':refs/remotes/origin/' + BASE_BRANCH]
    run('fetch-reviewed-base', fetch)
    assert git('rev-parse', 'FETCH_HEAD').decode().strip() == THEIRS
    run('base-ancestry', ['/usr/bin/git', 'merge-base', '--is-ancestor', BASE, THEIRS])
    native_paths = ['trillionnium', 'tests/fuzz', '.cargo', 'rust-toolchain', 'rust-toolchain.toml']
    run('upstream-native-source-equality', ['/usr/bin/git', 'diff', '--exit-code', BASE, THEIRS, '--', *native_paths])
    upstream_paths = set(git('diff', '--name-only', BASE, THEIRS).decode().splitlines())
    assert len(upstream_paths) == 25
    run('merge-reviewed-base', ['/usr/bin/git', 'merge', '--no-commit', '--no-ff', THEIRS], allowed=(0, 1))
    assert git('rev-parse', 'MERGE_HEAD').decode().strip() == THEIRS
    conflicts = set(git('diff', '--name-only', '--diff-filter=U').decode().splitlines())
    assert conflicts <= set(MERGED_SHA256)
    save(OUT / 'merge-conflicts.json', {'paths': sorted(conflicts), 'base': BASE, 'ours': OURS, 'theirs': THEIRS})
    for relative in MERGED_SHA256:
        current = (REPO / relative).read_bytes()
        (OUT / (relative.replace('/', '__') + '.raw')).write_bytes(current)
        (REPO / relative).write_bytes(git('show', OURS + ':' + relative))
    run('resolution-patch-check', ['/usr/bin/git', 'apply', '--check', str(OUT / 'overlap.patch')])
    run('resolution-patch-apply', ['/usr/bin/git', 'apply', str(OUT / 'overlap.patch')])
    for relative, expected in MERGED_SHA256.items():
        assert digest((REPO / relative).read_bytes()) == expected
    runner = REPO / RUNNER_REL
    assert not runner.exists()
    runner.write_bytes((OUT / 'authority-integrated-validation-runner.py').read_bytes())
    report = (REPO / REPORT).read_text()
    needle = 'records the actual tested successor and toolchain.\n'
    assert report.count(needle) == 1
    report = report.replace(needle, needle + '\nThis source also preserves concurrent migration qualification through\n'
        '`8d8f05566b2a1612a3bf4a6c6c71635df454d397`, including its independent CI\n'
        'controls. Execution records distinguish the original and integrated commits.\n')
    (REPO / REPORT).write_text(report)
    corpus = json.loads((REPO / CORPUS).read_text())
    assert EVIDENCE_REL + '/README.md' not in corpus['pinned_blobs']
    assert EVIDENCE_REL + '/artifact-index.json' not in corpus['pinned_blobs']
    for relative in [RUNNER_REL, REPORT]:
        corpus['pinned_blobs'][relative] = blob((REPO / relative).read_bytes())
    corpus['required_paths'] = sorted(set(corpus['required_paths']) | {RUNNER_REL})
    assert len(corpus['pinned_blobs']) == 722 and len(corpus['required_paths']) == 641
    assert len(corpus['assertions']) == 8 and all(v is False for v in corpus['assertions'].values())
    save(REPO / CORPUS, corpus)
    lock_relative = EVIDENCE_REL + '/.hepta-lock-51a6c3818e0946ef9891ba90'
    lock = REPO / lock_relative
    with lock.open('rb') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        st = os.fstat(stream.fileno())
        assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == 0
        assert lock.stat().st_ino == st.st_ino
        run('remove-inactive-tool-lock', ['/usr/bin/git', 'rm', '--', lock_relative])
    copied = checked_copy_tree(original, EVIDENCE / 'committed-source-01')
    save(OUT / 'original-validation-copy.json', copied)
    readme = EVIDENCE / 'README.md'
    text = readme.read_text()
    assert '## Exact-source validation before concurrent-base integration' not in text
    text += '\n## Exact-source validation before concurrent-base integration\n\n'
    text += ('The [first full run](committed-source-01/summary.json) passed all **28 command gates**\n'
        'on `62ed4e4facae4e0eb9f3fdeb82001acb3b21be47` (tree\n'
        '`38a1d4da1a6dc8c93d49ca181c8e35ecb79ef776`). It executed 52 release tests,\n'
        '442 tests across the other five selected packages, four doctests and 40 Node\n'
        'release-owner tests. Two existing cost observations and one isolated fixed-root\n'
        'Node control remained ignored; 1,244 unrelated Node tests were filtered out.\n'
        'This is not an all-workspace test run or full Node/Host acceptance.\n\n'
        'Formatting, locked offline graphs, strict all-target/all-feature workspace\n'
        'Clippy, Python guards, source integrity and repository links passed.\n'
        'Before/after source and provider identities matched, and actual retained\n'
        'SQLite build outputs were qualified. This run predates integration of\n'
        '`8d8f05566b2a1612a3bf4a6c6c71635df454d397`; it is not relabelled as a\n'
        'run on the merged source. All raw logs, including empty streams, are retained.\n')
    readme.write_text(text)
    index = rebuild_index()
    paths = [EVIDENCE_REL + '/' + name for name in index['files']]
    paths.append(EVIDENCE_REL + '/artifact-index.json')
    run('stage-source-resolution', ['/usr/bin/git', 'add', '--', *MERGED_SHA256, REPORT])
    run('stage-exact-evidence-inventory', ['/usr/bin/git', 'add', '--force', '--', *paths])
    assert not git('diff', '--name-only', '--diff-filter=U').strip()
    for relative, expected in index['files'].items():
        data = git('show', ':' + EVIDENCE_REL + '/' + relative)
        assert len(data) == expected['bytes'] and digest(data) == expected['sha256']
    changed = set(git('diff', '--cached', '--name-only', OURS).decode().splitlines())
    assert all(p in upstream_paths or p == REPORT or p.startswith(EVIDENCE_REL + '/') for p in changed)
    run('integrated-native-source-equality', ['/usr/bin/git', 'diff', '--cached', '--exit-code', OURS, '--', *native_paths])
    run('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
    run('staged-preflight', ['/bin/bash', 'scripts/project-preflight.sh', '--staged'])
    run('integrated-ci-contract-precheck', ['/usr/bin/python3', '-B', 'scripts/ci/check_ci_contract.py'])
    hold = run('integrated-pq-source-precheck', ['/usr/bin/python3', '-B', 'scripts/ci/check_pq_research_integration.py'])
    observed = json.loads(hold.stdout)
    assert observed['status'] == 'HOLD_NO_GO'
    assert observed['cryptographic_acceptance'] is False and observed['node_activated'] is False
    run('commit-integrated-source', ['/usr/bin/git', 'commit', '-m', 'merge(pq): retain concurrent migration qualification'])
    head = git('rev-parse', 'HEAD').decode().strip()
    parents = git('show', '-s', '--format=%P', 'HEAD').decode().split()
    assert parents == [OURS, THEIRS]
    assert not git('status', '--porcelain=v1', '--untracked-files=all').strip()
    receipt = {'result': 'PASS', 'source_commit': head, 'source_tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
        'parents': parents, 'branch': BRANCH, 'pinned_blobs': 722, 'required_paths': 641,
        'first_validation_commit': OURS, 'first_validation_gates': 28, 'production_activation': False,
        'whole_chain_pq_qualified': False, 'native_source_unchanged_from_first_validation': True,
        'artifact_index_files': len(index['files']), 'integrated_validation_executed': False}
    save(OUT / 'receipt.json', receipt)
    print(json.dumps(receipt), flush=True)

if __name__ == '__main__':
    main()
