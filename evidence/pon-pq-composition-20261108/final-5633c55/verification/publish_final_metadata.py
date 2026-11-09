#!/usr/bin/env python3
"""Publish a verified metadata child and update its existing HOLD Draft once."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import traceback

ROOT = Path('/home/qian-qi/work/chain-pq-composition-663507-20261108')
REPO = ROOT / 'repo'
REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
BRANCH = 'fix/chain-pq-composition-20261108-663507'
BASE_BRANCH = 'fix/chain-p0-unified-qualification-20261108-99b5'
BASE_HEAD = '7e044b65454f4c9ea505591727332acffb33e7e5'
RUNTIME_HEAD = '5633c55219c01c689f670c2ca35d122e39f3f791'
DATA_BRANCH = 'evidence/chain-pq-composition-20261108-663507'
VERIFY_SHA = '3fe2609803f69db1a133b66966466f0624442248ab0f3d2973e29e1839d8f076'
DATA_PUBLISHER_SHA = '0a315ddb827a5b47c76915293cef85c6fc15ba7fb6cc8359cfddf911f6bc6f23'
INITIAL_BODY = ROOT / 'pr-body-initial-terminal-5633.md'
INITIAL_BODY_SHA = '7a779294355e83097013b8204d7d8bc35b2b79132c3de91a80e35a9df2bd4b58'
PR_JQ = '{number,html_url,state,draft,title,body,user:.user.login,head:{ref:.head.ref,sha:.head.sha,repo:.head.repo.full_name},base:{ref:.base.ref,sha:.base.sha,repo:.base.repo.full_name}}'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'expected single-link regular file: ' + str(path))
    data = path.read_bytes()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            'file changed while read: ' + str(path))
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', required=True)
    parser.add_argument('--template-sha256', required=True)
    parser.add_argument('--continuation-sha256', required=True)
    args = parser.parse_args()
    head = args.head
    require(re.fullmatch('[0-9a-f]{40}', head), 'full publication head required')
    for digest in (args.template_sha256, args.continuation_sha256):
        require(re.fullmatch('[0-9a-f]{64}', digest), 'full input SHA-256 required')
    checks = ROOT / ('metadata-checks-' + head[:12])
    out = ROOT / ('publish-final-' + head[:12])
    template_path = ROOT / 'pr-body-final-template.md'
    continuation_path = ROOT / 'pr-body-continuation-final.md'
    data_publisher = ROOT / 'publish_verification_evidence.py'
    out.mkdir(exist_ok=False)
    runner_bytes = regular_bytes(Path(__file__))
    runner_sha = sha(runner_bytes)
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GH_PROMPT_DISABLED='1',
               GH_HOST='github.com', PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='0')
    result = {'status': 'INCOMPLETE', 'publication_head': head,
              'executed_runtime_head': RUNTIME_HEAD, 'runner_sha256_before': runner_sha,
              'whole_chain_pq_qualified': False, 'production_activation': False,
              'candidate_push_succeeded': False, 'evidence_push_succeeded': False,
              'draft_body_update_succeeded': False}

    def save(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')

    def run(label, argv, timeout=180, redact_stdout=False):
        started = time.time()
        receipt = {'argv': argv, 'cwd': str(REPO), 'started': started, 'attempts': 1}
        try:
            completed = subprocess.run(argv, cwd=REPO, env=env, capture_output=True, timeout=timeout)
            stdout, stderr = completed.stdout, completed.stderr
            receipt.update(exit_code=completed.returncode, timed_out=False)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            receipt.update(exit_code=None, timed_out=True)
        receipt.update(duration_seconds=time.time() - started,
                       stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
                       stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                       stdout_redacted=redact_stdout)
        if not redact_stdout:
            with (out / (label + '.stdout')).open('xb') as stream:
                stream.write(stdout)
        with (out / (label + '.stderr')).open('xb') as stream:
            stream.write(stderr)
        save(label + '.json', receipt)
        require(receipt['exit_code'] == 0 and not receipt['timed_out'],
                label + ': unsuccessful/unknown command; inspect receipts before any recovery')
        return stdout

    def source_guard(label):
        value = {'head': run(label + '-head', ['git', 'rev-parse', 'HEAD']).decode().strip(),
                 'tree': run(label + '-tree', ['git', 'rev-parse', 'HEAD^{tree}']).decode().strip(),
                 'branch': run(label + '-branch', ['git', 'branch', '--show-current']).decode().strip(),
                 'status': run(label + '-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all']).decode()}
        require(value['head'] == head and value['branch'] == BRANCH and value['status'] == '',
                'wrong or dirty publication source')
        save(label + '.json', value)
        return value

    def refs(label):
        raw = run(label, ['git', 'ls-remote', '--heads', 'origin',
                         'refs/heads/' + BRANCH, 'refs/heads/' + BASE_BRANCH,
                         'refs/heads/' + DATA_BRANCH]).decode().splitlines()
        found = {}
        for line in raw:
            oid, ref = line.split('\t')
            require(ref not in found and re.fullmatch('[0-9a-f]{40}', oid), 'invalid/duplicate remote ref')
            found[ref] = oid
        require(found.get('refs/heads/' + BASE_BRANCH) == BASE_HEAD, 'base branch changed')
        return found

    def read_pr(label, number=822):
        return json.loads(run(label, ['gh', 'api', f'repos/{REPOSITORY}/pulls/{number}', '--jq', PR_JQ]))

    def guard_pr(pr, expected_head, expected_body):
        require(pr['number'] == 822 and pr['state'] == 'open' and pr['draft'] is True and
                pr['user'] == 'ProfHepta', 'Draft identity/status changed')
        require(pr['head'] == {'ref': BRANCH, 'sha': expected_head, 'repo': REPOSITORY} and
                pr['base'] == {'ref': BASE_BRANCH, 'sha': BASE_HEAD, 'repo': REPOSITORY},
                'Draft source/base changed')
        require(pr['body'].replace('\r\n', '\n').rstrip() == expected_body.rstrip(),
                'Draft body changed; preserve concurrent content')

    def validate_raw_checks(verification, verification_bytes):
        names = [row['name'] for row in verification['commands']]
        expected_names = {'preflight', 'source-before', 'corpus', 'corpus-negatives',
                          'lifetime', 'authority-effects', 'authority-traces', 'claim-guard',
                          'ci-source-negatives', 'repository-markdown', 'repository-negatives',
                          'source-inventory', 'source-after'}
        require(len(names) == len(set(names)) == 13 and set(names) == expected_names,
                'unexpected source-check command identities')
        expected_counts = {'corpus-negatives': 58, 'ci-source-negatives': 43,
                           'repository-negatives': 50}
        captured = {}
        for directory, dirs, files in os.walk(checks, followlinks=False):
            for name in dirs:
                path = Path(directory) / name
                require(stat.S_ISDIR(path.lstat().st_mode) and not path.is_symlink(),
                        'nonregular source-check directory')
            for name in files:
                path = Path(directory) / name
                require(path.lstat().st_size <= 16 * 1024 * 1024, 'oversized source-check artifact')
                captured[path.relative_to(checks).as_posix()] = regular_bytes(path)
        require(captured.get('summary.json') == verification_bytes, 'validated source summary changed')
        require(sum(map(len, captured.values())) <= 32 * 1024 * 1024, 'oversized check packet')
        expected_files = {'summary.json', 'metadata-scope.json'}
        for row in verification['commands']:
            require(row['passed'] is True and row['attempts'] == 1 and row['exit_code'] == 0 and
                    row['timed_out'] is False, 'unsuccessful source command')
            count = expected_counts.get(row['name'])
            require(row['expected_unittest_count'] == count and
                    row['unittest_counts'] == ([count] if count is not None else []),
                    'wrong source-negative test roster')
            for stream in ('stdout', 'stderr'):
                path = row['name'] + '/' + stream + '.log'
                require(path in captured and sha(captured[path]) == row[stream + '_sha256'],
                        'source-check log mismatch: ' + path)
                expected_files.add(path)
            receipt = row['name'] + '/receipt.json'
            require(receipt in captured and json.loads(captured[receipt]) == row,
                    'source-check receipt mismatch: ' + receipt)
            expected_files.add(receipt)
        require(set(captured) == expected_files, 'missing or extra source-check artifacts')
        require(captured['source-before/stdout.log'] == captured['source-after/stdout.log'],
                'raw source identity receipts differ')
        scope = json.loads(captured['metadata-scope.json'])
        for key in ('publication_head', 'executed_runtime_head', 'runner_sha256_before',
                    'runtime_proof_workflow_test_bytes_unchanged',
                    'prior_evidence_blobs_and_modes_preserved_except_readme',
                    'prior_failed_observations_replaced', 'corpus_changes_are_two_documentation_pins'):
            require(scope.get(key) == verification.get(key), 'source-check scope mismatch: ' + key)
        return [{'path': name, 'bytes': len(data), 'sha256': sha(data)}
                for name, data in sorted(captured.items())]

    try:
        require(checks.is_dir() and not checks.is_symlink() and checks.resolve().parent == ROOT,
                'unexpected metadata check directory')
        verification_bytes = regular_bytes(checks / 'summary.json')
        verification = json.loads(verification_bytes)
        require(verification['status'] == 'PASS_METADATA_SOURCE_CHECKS_HOLD' and
                verification['publication_head'] == head and verification['executed_runtime_head'] == RUNTIME_HEAD,
                'wrong or unsuccessful metadata verification')
        require(verification['source_negative_cases'] == 151 and len(verification['commands']) == 13 and
                all(row['passed'] and row['attempts'] == 1 for row in verification['commands']),
                'incomplete metadata source checks')
        require(verification['runner_sha256_before'] == VERIFY_SHA == verification['runner_sha256_after'] and
                verification['source_receipts_equal'] is True and
                verification['runtime_proof_workflow_test_bytes_unchanged'] is True and
                verification['prior_evidence_blobs_and_modes_preserved_except_readme'] is True and
                verification['prior_failed_observations_replaced'] is False and
                verification['corpus_changes_are_two_documentation_pins'] is True,
                'missing verified source/evidence invariant')
        require(verification['native_tests_executed'] is False and
                verification['whole_chain_pq_qualified'] is False and
                verification['production_activation'] is False, 'unsupported qualification in verification')
        initial_bytes = regular_bytes(INITIAL_BODY)
        template_bytes = regular_bytes(template_path)
        continuation_bytes = regular_bytes(continuation_path)
        require(sha(initial_bytes) == INITIAL_BODY_SHA, 'initial body changed')
        require(sha(template_bytes) == args.template_sha256, 'template changed')
        require(sha(continuation_bytes) == args.continuation_sha256, 'continuation text changed')
        data_publisher_bytes = regular_bytes(data_publisher)
        require(sha(data_publisher_bytes) == DATA_PUBLISHER_SHA, 'data publisher changed')
        template, continuation, initial_body = (item.decode('utf-8') for item in
                                                 (template_bytes, continuation_bytes, initial_bytes))
        tokens = re.findall(r'\{\{[A-Z_]+\}\}', template)
        require(sorted(tokens) == sorted(['{{PUBLICATION_HEAD}}', '{{PUBLICATION_HEAD}}',
                                         '{{CONTINUATION_RESULTS}}', '{{PUBLICATION_SOURCE_RESULTS}}',
                                         '{{PUBLICATION_RECEIPT_URL}}']), 'unexpected template slots')
        require('{{' not in continuation and continuation.strip(), 'unresolved/empty continuation text')
        save('intent.json', {'head': head, 'runtime_head': RUNTIME_HEAD,
                             'runner_sha256': runner_sha, 'template_sha256': args.template_sha256,
                             'continuation_sha256': args.continuation_sha256,
                             'source_verification_summary_sha256': sha(verification_bytes),
                             'data_publisher_sha256': DATA_PUBLISHER_SHA,
                             'actions': ['ordinary candidate push', 'separate data-ref publication', 'existing Draft body update']})
        run('preflight-before', ['bash', 'scripts/project-preflight.sh'])
        before_source = source_guard('source-before')
        require(run('single-parent', ['git', 'rev-list', '--parents', '-n', '1', head]).decode().split()
                == [head, RUNTIME_HEAD], 'not the single metadata child')
        require(run('actor-before', ['gh', 'api', 'user', '--jq', '.login']).decode().strip() == 'ProfHepta',
                'wrong native GitHub actor')
        origin = run('origin', ['git', 'remote', 'get-url', 'origin'], redact_stdout=True).decode().strip()
        require(origin in {f'https://github.com/{REPOSITORY}', f'https://github.com/{REPOSITORY}.git',
                           f'git@github.com:{REPOSITORY}.git'}, 'unexpected origin')
        before_refs = refs('remote-refs-before')
        require(before_refs.get('refs/heads/' + BRANCH) == RUNTIME_HEAD and
                'refs/heads/' + DATA_BRANCH not in before_refs, 'publication refs drifted; read back before recovery')
        base_pr = read_pr('base-pr-before', 812)
        require(base_pr['state'] == 'open' and base_pr['draft'] is True and
                base_pr['head'] == {'ref': BASE_BRANCH, 'sha': BASE_HEAD, 'repo': REPOSITORY},
                'base Draft changed')
        before_pr = read_pr('draft-before')
        guard_pr(before_pr, RUNTIME_HEAD, initial_body)
        require(source_guard('source-pre-push') == before_source, 'source changed before candidate push')
        require(regular_bytes(checks / 'summary.json') == verification_bytes and
                regular_bytes(Path(__file__)) == runner_bytes, 'verification or publisher changed before push')
        save('pre-push-raw-checks.json', validate_raw_checks(verification, verification_bytes))
        run('preflight-push', ['bash', 'scripts/project-preflight.sh'])
        run('push-candidate', ['git', 'push', '--porcelain', 'origin', head + ':refs/heads/' + BRANCH], timeout=600)
        require(refs('remote-refs-after-candidate').get('refs/heads/' + BRANCH) == head, 'candidate push readback mismatch')
        result['candidate_push_succeeded'] = True
        guard_pr(read_pr('draft-after-candidate'), head, initial_body)
        require(regular_bytes(data_publisher) == data_publisher_bytes,
                'data publisher changed before execution')
        run('publish-verification-receipts', ['/usr/bin/python3.12', '-B', str(data_publisher), '--head', head], timeout=1200)
        evidence_bytes = regular_bytes(ROOT / ('publish-source-evidence-' + head[:12]) / 'summary.json')
        evidence = json.loads(evidence_bytes)
        require(evidence['status'] == 'PUBLISHED_DATA_ONLY_RECEIPTS' and evidence['publication_head'] == head and
                evidence['executed_runtime_head'] == RUNTIME_HEAD and
                evidence['source_verification_summary_sha256'] == sha(verification_bytes) and
                evidence['source_identity_unchanged'] is True and
                evidence['candidate_ref_write_commands_executed'] is False and
                evidence['working_tree_write_commands_executed'] is False and
                evidence['runner_sha256_before'] == DATA_PUBLISHER_SHA == evidence['runner_sha256_after'],
                'invalid data-publication receipt')
        evidence_commit = evidence['evidence_commit']
        require(re.fullmatch('[0-9a-f]{40}', evidence_commit), 'invalid evidence commit')
        receipt_url = f'https://github.com/{REPOSITORY}/blob/{evidence_commit}/evidence/pon-pq-composition-20261108/publication-checks/summary.json'
        require(evidence['receipt_url'] == receipt_url, 'unexpected source receipt URL')
        data_refs = refs('remote-refs-after-evidence')
        require(data_refs.get('refs/heads/' + BRANCH) == head and
                data_refs.get('refs/heads/' + DATA_BRANCH) == evidence_commit, 'published refs changed')
        result.update(evidence_push_succeeded=True, evidence_commit=evidence_commit,
                      evidence_summary_sha256=sha(evidence_bytes), receipt_url=receipt_url)
        source_text = ('On publication commit `' + head + '`, all **13 source commands passed**, including '
                       '**151 source-negative cases** (58 corpus + 43 CI-source integrity + 50 repository controls). '
                       'Raw source and verification-runner readbacks matched before/after. The comparison to executed '
                       '`5633...` retains identical runtime, proof, workflow and test bytes; earlier raw evidence blobs '
                       'and modes are unchanged except the evidence README. Only the two documentation corpus pins '
                       'were rebound. These checks executed no native tests and confer no whole-chain qualification.')
        replacements = {'{{PUBLICATION_HEAD}}': head, '{{CONTINUATION_RESULTS}}': continuation.rstrip(),
                        '{{PUBLICATION_SOURCE_RESULTS}}': source_text,
                        '{{PUBLICATION_RECEIPT_URL}}': receipt_url}
        body = template
        for token, value in replacements.items():
            body = body.replace(token, value)
        require('{{' not in body and '}}' not in body, 'unresolved body template')
        body_bytes = body.encode('utf-8')
        body_path = out / 'pr-body-final.md'
        with body_path.open('xb') as stream:
            stream.write(body_bytes)
        require(source_guard('source-pre-update') == before_source, 'source changed before Draft update')
        require(regular_bytes(template_path) == template_bytes and
                regular_bytes(continuation_path) == continuation_bytes and
                regular_bytes(Path(__file__)) == runner_bytes and
                regular_bytes(data_publisher) == data_publisher_bytes and
                regular_bytes(body_path) == body_bytes, 'publication inputs changed')
        run('preflight-body', ['bash', 'scripts/project-preflight.sh'])
        # This narrows the observed read/write window; gh pr edit provides no
        # atomic body compare-and-swap against a simultaneous external writer.
        guard_pr(read_pr('draft-pre-update'), head, initial_body)
        run('update-draft-body', ['gh', 'pr', 'edit', '822', '--repo', REPOSITORY,
                                  '--body-file', str(body_path)], timeout=300)
        actual = read_pr('draft-after')
        guard_pr(actual, head, body)
        require(actual['title'] == before_pr['title'], 'Draft title changed')
        final_refs = refs('remote-refs-final')
        require(final_refs.get('refs/heads/' + BRANCH) == head and
                final_refs.get('refs/heads/' + DATA_BRANCH) == evidence_commit, 'final ref drift')
        require(source_guard('source-after') == before_source, 'source changed during publication')
        require(run('actor-after', ['gh', 'api', 'user', '--jq', '.login']).decode().strip() == 'ProfHepta',
                'native GitHub actor changed')
        require(regular_bytes(checks / 'summary.json') == verification_bytes and
                regular_bytes(Path(__file__)) == runner_bytes, 'verification/publisher changed')
        result.update(status='PUBLISHED_METADATA_AND_RECEIPTS_DRAFT_HOLD', draft_body_update_succeeded=True,
                      source_unchanged=True, pr=actual, body_sha256=sha(body_bytes),
                      source_verification_summary_sha256=sha(verification_bytes),
                      runner_sha256_after=runner_sha)
    except BaseException as error:
        result.update(status='FAILED_OR_UNCERTAIN_REQUIRES_READBACK',
                      error=type(error).__name__ + ': ' + str(error), traceback=traceback.format_exc())
        raise
    finally:
        result['finished'] = time.time()
        save('summary.json', result)
        print(json.dumps({key: value for key, value in result.items() if key != 'pr'}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
