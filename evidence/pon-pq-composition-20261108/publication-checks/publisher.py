#!/usr/bin/env python3
"""Persist completed publication checks on a separate data ref, without moving the candidate."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import time

ROOT = Path('/home/qian-qi/work/chain-pq-composition-663507-20261108')
REPO = ROOT / 'repo'
REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
CANDIDATE_BRANCH = 'fix/chain-pq-composition-20261108-663507'
DATA_BRANCH = 'evidence/chain-pq-composition-20261108-663507'
RUNTIME_HEAD = '5633c55219c01c689f670c2ca35d122e39f3f791'
VERIFY_SHA = '3fe2609803f69db1a133b66966466f0624442248ab0f3d2973e29e1839d8f076'
PREFIX = 'evidence/pon-pq-composition-20261108/publication-checks/'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', required=True)
    args = parser.parse_args()
    head = args.head
    require(re.fullmatch('[0-9a-f]{40}', head), 'full publication head required')
    checks = ROOT / ('metadata-checks-' + head[:12])
    out = ROOT / ('publish-source-evidence-' + head[:12])
    out.mkdir(exist_ok=False)
    runner_bytes = Path(__file__).read_bytes()
    runner_sha = sha(runner_bytes)
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GH_PROMPT_DISABLED='1', GH_HOST='github.com')
    result = {'status': 'INCOMPLETE', 'publication_head': head,
              'executed_runtime_head': RUNTIME_HEAD, 'data_branch': DATA_BRANCH,
              'candidate_ref_write_commands_executed': False,
              'working_tree_write_commands_executed': False,
              'source_identity_unchanged': None,
              'whole_chain_pq_qualified': False, 'production_activation': False,
              'runner_sha256_before': runner_sha}

    def save(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')

    def run(label, argv, input_bytes=None, index=False, timeout=180):
        begin = time.time()
        child_env = dict(env)
        if index:
            child_env['GIT_INDEX_FILE'] = str(out / 'temporary-index')
        try:
            completed = subprocess.run(argv, cwd=REPO, env=child_env, input=input_bytes,
                                       capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            (out / (label + '.stdout')).write_bytes(stdout)
            (out / (label + '.stderr')).write_bytes(stderr)
            save(label + '.json', {'argv': argv, 'cwd': str(REPO), 'exit_code': None,
                                  'timed_out': True, 'duration_seconds': time.time() - begin,
                                  'temporary_index': index,
                                  'input_sha256': sha(input_bytes) if input_bytes is not None else None,
                                  'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)})
            raise
        (out / (label + '.stdout')).write_bytes(completed.stdout)
        (out / (label + '.stderr')).write_bytes(completed.stderr)
        save(label + '.json', {'argv': argv, 'cwd': str(REPO), 'exit_code': completed.returncode,
                              'duration_seconds': time.time() - begin,
                              'temporary_index': index, 'input_sha256': sha(input_bytes) if input_bytes is not None else None,
                              'stdout_sha256': sha(completed.stdout), 'stderr_sha256': sha(completed.stderr)})
        require(completed.returncode == 0, label + ': nonzero exit; inspect retained receipt')
        return completed.stdout

    def source_guard(label):
        value = {'head': run(label + '-head', ['git', 'rev-parse', 'HEAD']).decode().strip(),
                 'tree': run(label + '-tree', ['git', 'rev-parse', 'HEAD^{tree}']).decode().strip(),
                 'branch': run(label + '-branch', ['git', 'branch', '--show-current']).decode().strip(),
                 'status': run(label + '-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all']).decode()}
        require(value['head'] == head and value['branch'] == CANDIDATE_BRANCH and value['status'] == '',
                'candidate source identity changed')
        save(label + '.json', value)
        return value

    def remote_ref(label, branch):
        raw = run(label, ['git', 'ls-remote', '--heads', 'origin', 'refs/heads/' + branch]).decode().splitlines()
        require(len(raw) <= 1, 'ambiguous remote ref')
        if not raw:
            return None
        oid, ref = raw[0].split('\t')
        require(ref == 'refs/heads/' + branch, 'wrong returned ref')
        return oid

    try:
        require(not checks.is_symlink() and checks.resolve().parent == ROOT and checks.is_dir(),
                'checks must be the expected owned directory')
        summary_path = checks / 'summary.json'
        require(stat.S_ISREG(summary_path.lstat().st_mode), 'nonregular check summary')
        summary_bytes = summary_path.read_bytes()
        verification = json.loads(summary_bytes)
        require(verification['status'] == 'PASS_METADATA_SOURCE_CHECKS_HOLD', 'source checks did not pass')
        require(verification['publication_head'] == head and verification['executed_runtime_head'] == RUNTIME_HEAD,
                'wrong verified source')
        require(verification['source_negative_cases'] == 151 and len(verification['commands']) == 13,
                'unexpected check coverage')
        require(all(row['passed'] and row['attempts'] == 1 for row in verification['commands']), 'unsuccessful command')
        require(verification['source_receipts_equal'] is True and
                verification['runtime_proof_workflow_test_bytes_unchanged'] is True and
                verification['prior_evidence_blobs_and_modes_preserved_except_readme'] is True and
                verification['prior_failed_observations_replaced'] is False, 'missing identity/evidence condition')
        require(verification['runner_sha256_before'] == VERIFY_SHA == verification['runner_sha256_after'],
                'wrong verification runner')
        require(verification['native_tests_executed'] is False and
                verification['whole_chain_pq_qualified'] is False and
                verification['production_activation'] is False, 'unsupported qualification')
        run('preflight', ['bash', 'scripts/project-preflight.sh'])
        before_source = source_guard('source-before')
        require(run('actor-before', ['gh', 'api', 'user', '--jq', '.login']).decode().strip() == 'ProfHepta',
                'wrong GitHub actor')
        origin = run('origin', ['git', 'remote', 'get-url', 'origin']).decode().strip()
        require(origin in {f'https://github.com/{REPOSITORY}', f'https://github.com/{REPOSITORY}.git',
                           f'git@github.com:{REPOSITORY}.git'}, 'unexpected origin')
        require(remote_ref('candidate-ref-before', CANDIDATE_BRANCH) == head, 'candidate not published at verified head')
        require(remote_ref('data-ref-before', DATA_BRANCH) is None, 'data ref already exists; read back instead of retrying')
        original_summary = sha(summary_bytes)
        members = []
        for directory, dirs, files in os.walk(checks, followlinks=False):
            for name in dirs:
                mode = (Path(directory) / name).lstat().st_mode
                require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), 'nonregular directory in checks')
            for name in files:
                path = Path(directory) / name
                start = path.lstat()
                require(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and start.st_size <= 16 * 1024 * 1024,
                        'unsupported check artifact')
                data = path.read_bytes()
                end = path.lstat()
                require((start.st_dev, start.st_ino, start.st_size, start.st_mtime_ns, start.st_ctime_ns) ==
                        (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns), 'artifact changed while read')
                members.append((path.relative_to(checks).as_posix(), data))
        require(0 < len(members) <= 200 and sum(len(data) for _, data in members) <= 32 * 1024 * 1024,
                'unexpected receipt footprint')
        captured = dict(members)
        require(len(captured) == len(members), 'duplicate captured path')
        require(captured.get('summary.json') == summary_bytes, 'captured summary differs from validated bytes')
        expected_names = {
            'preflight', 'source-before', 'corpus', 'corpus-negatives', 'lifetime',
            'authority-effects', 'authority-traces', 'claim-guard', 'ci-source-negatives',
            'repository-markdown', 'repository-negatives', 'source-inventory', 'source-after',
        }
        names = [row['name'] for row in verification['commands']]
        require(len(names) == len(set(names)) and set(names) == expected_names, 'wrong command identities')
        expected_files = {'summary.json', 'metadata-scope.json'}
        for row in verification['commands']:
            for stream in ('stdout', 'stderr'):
                path = row['name'] + '/' + stream + '.log'
                require(path in captured and sha(captured[path]) == row[stream + '_sha256'],
                        'command log differs from validated summary: ' + path)
                expected_files.add(path)
            receipt = row['name'] + '/receipt.json'
            require(receipt in captured and json.loads(captured[receipt]) == row,
                    'command receipt differs from validated summary: ' + receipt)
            expected_files.add(receipt)
        require(set(captured) == expected_files, 'unexpected or missing check artifacts')
        require(captured['source-before/stdout.log'] == captured['source-after/stdout.log'],
                'raw source readbacks differ')
        scope = json.loads(captured['metadata-scope.json'])
        for key in ('publication_head', 'executed_runtime_head', 'runner_sha256_before',
                    'runtime_proof_workflow_test_bytes_unchanged',
                    'prior_evidence_blobs_and_modes_preserved_except_readme',
                    'prior_failed_observations_replaced', 'corpus_changes_are_two_documentation_pins'):
            require(scope.get(key) == verification.get(key), 'scope record differs: ' + key)
        archive = out / 'publication-source-checks.tar.gz'
        with archive.open('xb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode='w') as stream:
                    for name, data in sorted(members):
                        info = tarfile.TarInfo(name)
                        info.size, info.mode = len(data), 0o644
                        stream.addfile(info, io.BytesIO(data))
        with tarfile.open(archive, 'r:gz') as stream:
            require(len(stream.getmembers()) == len(members), 'wrong archive member count')
            for name, data in members:
                item = stream.getmember(name)
                require(item.isfile() and stream.extractfile(item).read() == data, 'archive readback mismatch')
        manifest = {'schema': 'trnm-publication-checks-archive-v1', 'publication_head': head,
                    'executed_runtime_head': RUNTIME_HEAD, 'source_negative_cases': 151,
                    'whole_chain_pq_qualified': False, 'native_tests_executed': False,
                    'archive': archive.name, 'archive_sha256': sha(archive.read_bytes()),
                    'members': [{'path': name, 'bytes': len(data), 'sha256': sha(data)} for name, data in sorted(members)]}
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
        payloads = {PREFIX + archive.name: archive.read_bytes(),
                    PREFIX + 'manifest.json': manifest_bytes,
                    PREFIX + 'summary.json': summary_bytes,
                    PREFIX + 'publisher.py': runner_bytes}
        require(sha(payloads[PREFIX + 'summary.json']) == original_summary, 'summary changed')
        require(sha(payloads[PREFIX + 'publisher.py']) == runner_sha, 'publisher payload differs')
        run('index-base', ['git', 'read-tree', head], index=True)
        objects = {}
        for index, (path, data) in enumerate(sorted(payloads.items())):
            existing = run(f'new-path-{index}', ['git', 'ls-tree', head, '--', path])
            require(existing == b'', 'receipt path already exists in candidate')
            oid = run(f'blob-{index}', ['git', 'hash-object', '-w', '--stdin'], input_bytes=data).decode().strip()
            require(re.fullmatch('[0-9a-f]{40}', oid), 'invalid blob oid')
            run(f'index-add-{index}', ['git', 'update-index', '--add', '--cacheinfo', '100644,' + oid + ',' + path], index=True)
            objects[path] = oid
        tree = run('receipt-tree', ['git', 'write-tree'], index=True).decode().strip()
        author = run('candidate-author', ['git', 'show', '-s', '--format=%an%x00%ae', head]).decode().strip().split('\0')
        require(len(author) == 2 and author[0] == 'Codex' and '\n' not in author[1], 'unexpected candidate author')
        env.update(GIT_AUTHOR_NAME=author[0], GIT_AUTHOR_EMAIL=author[1],
                   GIT_COMMITTER_NAME=author[0], GIT_COMMITTER_EMAIL=author[1])
        message = ('Record exact publication source checks for ' + head + '\n\n'
                   'Store completed checks on a separate evidence ref while preserving the candidate head.\n'
                   'Native source remains ' + RUNTIME_HEAD + '; whole-chain PQ and activation remain unqualified.\n\n'
                   'Signed-off-by: ' + author[0] + ' <' + author[1] + '>\n').encode()
        commit = run('receipt-commit', ['git', 'commit-tree', tree, '-p', head], input_bytes=message).decode().strip()
        require(re.fullmatch('[0-9a-f]{40}', commit), 'invalid receipt commit')
        changes = run('receipt-diff', ['git', 'diff', '--no-renames', '--name-status', head, commit]).decode().splitlines()
        require(sorted(changes) == sorted('A\t' + path for path in payloads), 'receipt commit changed candidate files')
        for index, (path, oid) in enumerate(sorted(objects.items())):
            require(run(f'committed-blob-{index}', ['git', 'rev-parse', commit + ':' + path]).decode().strip() == oid,
                    'committed receipt object mismatch')
        save('prepared-data-commit.json', {'commit': commit, 'tree': tree, 'parent': head, 'objects': objects,
                                          'archive_sha256': manifest['archive_sha256']})
        require(source_guard('source-pre-push') == before_source, 'candidate changed before data push')
        require(stat.S_ISREG(summary_path.lstat().st_mode) and sha(summary_path.read_bytes()) == original_summary,
                'validated summary changed before push')
        require(sha(Path(__file__).read_bytes()) == runner_sha, 'publisher changed before push')
        run('preflight-push', ['bash', 'scripts/project-preflight.sh'])
        run('push-data-ref', ['git', 'push', '--porcelain', 'origin', commit + ':refs/heads/' + DATA_BRANCH], timeout=600)
        require(remote_ref('data-ref-after', DATA_BRANCH) == commit, 'data ref readback mismatch')
        require(remote_ref('candidate-ref-after', CANDIDATE_BRANCH) == head, 'candidate ref moved')
        require(source_guard('source-after') == before_source, 'working source changed')
        require(run('actor-after', ['gh', 'api', 'user', '--jq', '.login']).decode().strip() == 'ProfHepta', 'actor changed')
        require(sha(Path(__file__).read_bytes()) == runner_sha, 'publisher changed')
        result.update(status='PUBLISHED_DATA_ONLY_RECEIPTS', evidence_commit=commit, evidence_tree=tree,
                      source_identity_unchanged=True,
                      archive_sha256=manifest['archive_sha256'], source_verification_summary_sha256=original_summary,
                      receipt_url=f'https://github.com/{REPOSITORY}/blob/{commit}/{PREFIX}summary.json',
                      runner_sha256_after=runner_sha)
    except BaseException as error:
        result.update(status='FAILED_OR_UNCERTAIN_REQUIRES_READBACK', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        save('summary.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
