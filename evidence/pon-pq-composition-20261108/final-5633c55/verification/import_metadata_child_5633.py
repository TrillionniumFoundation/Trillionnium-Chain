#!/usr/bin/env python3
"""Import one metadata-only child of 5633 and run the frozen source verifier.

This task-specific importer never pushes, runs Cargo, changes Git configuration,
or retries. A failed verification may leave the local branch at the imported Y;
its receipt records that state and does not roll back or publish it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

ROOT = Path('/home/qian-qi/work/chain-pq-composition-663507-20261108')
REPO = ROOT / 'repo'
BASE = '5633c55219c01c689f670c2ca35d122e39f3f791'
BASE_TREE = '3baafa8923d1a1e7bfb6f24cff9965a4e82fba4c'
REF = 'refs/heads/fix/chain-pq-composition-20261108-663507'
PYTHON = '/usr/bin/python3.12'
VERIFIER = ROOT / 'verify_metadata_publication.py'
VERIFY_SHA = '3fe2609803f69db1a133b66966466f0624442248ab0f3d2973e29e1839d8f076'
TERMINAL_FILE = ROOT / 'metadata_import_terminal_evidence_5633.json'
TERMINAL_SHA = '9767b7ad4c41d76fef47e2657f3ba6b2dbda1aab56204a8a1d817ee32fe00fed'
DOCS = ('docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md',
        'docs/security/PQ_COMPOSITION_20261108.md')
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
EVIDENCE = 'evidence/pon-pq-composition-20261108/'
CGROOT = Path('/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice')
JOBS = {
    'parallel_main': ('1a1bc526042-138b0-1aa', 'failed', 1),
    'bounded_io': ('1a1bc6ad0fc-138b0-257', 'succeeded', 0),
    'da_recovery': ('1a1bc9287f7-138b0-354', 'succeeded', 0),
    'original_node_two_case': ('1a1bcaf5f3b-138b0-408', 'succeeded', 0),
    'native_continuation': ('1a1bcd5be33-138b0-4c5', 'failed', 1),
    'cache_inspection': ('1a1bce1ff35-138b0-4fa', 'succeeded', 0),
    'cache_deletion': ('1a1bce4f3dd-138b0-508', 'succeeded', 0),
}
DA_INTENT = ROOT / 'da-fixture-diagnostics-5633/output/execution-intent.json'
DA_INTENT_SHA = 'bae51865d6cc3dac17f9b8db8658508ca065b023d79357995b3e02859ad4186d'
CHECK_NAMES = ('preflight', 'source-before', 'corpus', 'corpus-negatives', 'lifetime',
               'authority-effects', 'authority-traces', 'claim-guard', 'ci-source-negatives',
               'repository-markdown', 'repository-negatives', 'source-inventory', 'source-after')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def open_parent(path):
    require(path.is_absolute() and '..' not in path.parts, 'absolute normalized path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def file_record(path, expected=None, read=False):
    parent = open_parent(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular single-link file required: ' + str(path))
        h = hashlib.sha256()
        chunks = []
        length = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
            length += len(block)
            if read:
                chunks.append(block)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(after) and length == before.st_size, 'file changed during read: ' + str(path))
        record = {'path': str(path), 'bytes': length, 'sha256': h.hexdigest(),
                  'device': before.st_dev, 'inode': before.st_ino, 'mode': before.st_mode}
        require(expected is None or record['sha256'] == expected, 'input SHA mismatch: ' + str(path))
        return (record, b''.join(chunks)) if read else record
    finally:
        os.close(fd)


def save(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def terminal_guard():
    identity, raw = file_record(TERMINAL_FILE, TERMINAL_SHA, read=True)
    d = json.loads(raw)
    require(d['schema'] == 'trnm-metadata-import-terminal-evidence-v1' and d['source_head'] == BASE, 'terminal evidence scope mismatch')
    require(set(d['jobs']) == set(JOBS) and d['parallel_main_covers_roles'] == ['source', 'proof', 'owner', 'native'], 'terminal role roster changed')
    absent = []
    for role, (job, state, code) in JOBS.items():
        supplied = d['jobs'][role]
        tool = supplied['raw_tool_result']
        require(not tool.get('isError'), 'terminal tool error: ' + role)
        observed = json.loads('\n'.join(x['text'] for x in tool['content'] if x['type'] == 'text'))
        require(observed == supplied['observed'], 'terminal parsed/raw mismatch: ' + role)
        require(observed['job_id'] == job and observed['state'] == state and observed['exit_code'] == code,
                'wrong terminal state: ' + role)
        require(all(observed[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed')), 'incomplete terminal evidence: ' + role)
        p = CGROOT / ('hepta-runtime-job-' + job + '.service')
        try:
            p.lstat()
        except FileNotFoundError:
            absent.append({'job_id': job, 'cgroup': str(p), 'present': False})
        else:
            raise RuntimeError('known job cgroup still present: ' + job)
    unknown = d['da_original_unknown']
    require(unknown['job_id'] == '1a1bc8399f6-138b0-2f7' and
            unknown['launch_state'] == 'launch_unknown' and unknown['cancel_state'] == 'cancel_unknown' and
            unknown['termination_confirmed'] is False and unknown['reclassified'] is False, 'DA unknown state changed')
    intent = file_record(DA_INTENT, DA_INTENT_SHA)
    require(intent['bytes'] == 515 and unknown['intent'] == {'path': str(DA_INTENT), 'bytes': 515, 'sha256': DA_INTENT_SHA}, 'DA preserved intent mismatch')
    require(d['no_future_native_or_cleanup_launch_authorized_by_this_evidence'] is True and
            d['source_identity_still_required_at_import'] is True and d['whole_chain_pq_qualified'] is False,
            'terminal evidence claim changed')
    return {'terminal_input': identity, 'known_cgroups_absent': absent, 'da_unknown_retained': True, 'da_intent': intent}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', required=True)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--bundle-sha256', required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.head) and args.head != BASE, 'full new Y required')
    require(args.ref == REF, 'wrong candidate ref')
    require(re.fullmatch('[0-9a-f]{64}', args.bundle_sha256), 'full bundle SHA required')
    require(args.bundle.parent == ROOT and args.bundle.name.endswith('.bundle'), 'bundle must be a direct task-root .bundle file')
    require(Path(__file__).absolute() == ROOT / 'import_metadata_child_5633.py', 'unexpected importer location')
    for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY',
                'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_REPLACE_REF_BASE'):
        require(key not in os.environ, 'unexpected Git environment override: ' + key)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GIT_TERMINAL_PROMPT='0',
               GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0')
    out = ROOT / ('metadata-import-' + args.head[:12])
    checks = ROOT / ('metadata-checks-' + args.head[:12])
    require(not checks.exists() and not checks.is_symlink(), 'verifier output must be fresh')
    parent = open_parent(out)
    try:
        os.mkdir(out.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)
    save(out / 'execution-intent.json', {'head': args.head, 'ref': REF, 'bundle': str(args.bundle),
        'bundle_sha256': args.bundle_sha256, 'attempts': 1, 'created_unix': time.time()})
    result = {'schema': 'trnm-metadata-child-import-v1', 'head_requested': args.head,
              'runtime_head': BASE, 'candidate_ref': REF, 'status': 'INCOMPLETE', 'commands': [],
              'native_tests_executed': False, 'push_executed': False, 'whole_chain_pq_qualified': False,
              'production_activation': False, 'prior_failed_observations_replaced': None,
              'objects_import_attempted': False, 'fast_forward_attempted': False, 'verifier_attempted': False,
              'automatic_retry': False, 'rollback_attempted': False}
    runner_before = None

    def run(label, argv, timeout=300):
        directory = out / label
        directory.mkdir()
        row = {'name': label, 'argv': argv, 'cwd': str(REPO), 'attempts': 1,
               'started_unix': time.time(), 'exit_code': None, 'timed_out': False, 'pid': None}
        proc = None
        begin = time.monotonic()
        try:
            with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
                proc = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr, start_new_session=True)
                row['pid'] = proc.pid
                try:
                    row['exit_code'] = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
        except BaseException as e:
            row['error'] = type(e).__name__ + ': ' + str(e)
        finally:
            if proc is not None and (row['timed_out'] or row.get('error') or row['exit_code'] != 0):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                row['exit_code'] = proc.returncode
            row['elapsed_seconds'] = time.monotonic() - begin
            for stream in ('stdout', 'stderr'):
                path = directory / (stream + '.log')
                if path.exists():
                    row[stream] = file_record(path)
            row['passed'] = row['exit_code'] == 0 and not row['timed_out'] and not row.get('error')
            save(directory / 'receipt.json', row)
            result['commands'].append(row)
            print(json.dumps({'command': label, 'exit_code': row['exit_code'], 'passed': row['passed']}), flush=True)
        require(row['passed'], 'command failed or incomplete: ' + label)
        return (directory / 'stdout.log').read_bytes()

    def git(label, *argv):
        return run(label, ['/usr/bin/git', '--no-replace-objects', *argv])

    def source(label, expected):
        return run(label, [PYTHON, '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                          '--expected-head', expected], timeout=1800)

    def identity(label, expected, tree=None):
        values = git(label + '-identity', 'rev-parse', 'HEAD', 'HEAD^{tree}').decode().splitlines()
        require(values[0] == expected and (tree is None or values[1] == tree), 'wrong source identity')
        require(git(label + '-branch', 'symbolic-ref', 'HEAD').decode().strip() == REF, 'wrong current branch')
        require(git(label + '-clean', 'status', '--porcelain=v1', '-z', '--untracked-files=all') == b'', 'dirty source')
        return {'head': values[0], 'tree': values[1]}

    try:
        runner_before = file_record(Path(__file__).absolute())
        result['runner_before'] = runner_before
        result['bundle_before'] = file_record(args.bundle, args.bundle_sha256)
        result['verifier_before'] = file_record(VERIFIER, VERIFY_SHA)
        result['terminal_before'] = terminal_guard()
        result['source_before'] = identity('before', BASE, BASE_TREE)
        run('project-preflight', ['/bin/bash', 'scripts/project-preflight.sh'])
        source('source-before', BASE)
        git('bundle-verify', 'bundle', 'verify', str(args.bundle))
        expected_heads = (args.head + ' ' + REF + '\n').encode()
        require(git('bundle-list-heads', 'bundle', 'list-heads', str(args.bundle)) == expected_heads,
                'bundle must advertise exactly the requested Y/ref')
        refs_before = git('refs-before', 'for-each-ref', '--format=%(refname) %(objectname)')
        result['objects_import_attempted'] = True
        require(git('bundle-unbundle', 'bundle', 'unbundle', str(args.bundle)) == expected_heads, 'unbundle advertised heads changed')
        require(file_record(args.bundle, args.bundle_sha256) == result['bundle_before'], 'bundle identity changed')
        require(git('refs-after-unbundle', 'for-each-ref', '--format=%(refname) %(objectname)') == refs_before,
                'object import changed refs')
        require(git('single-parent', 'rev-list', '--parents', '-n', '1', args.head).decode().split() == [args.head, BASE],
                'Y is not a direct single child of 5633')
        changed = git('changed-paths', 'diff', '--no-renames', '--name-only', '-z', BASE, args.head).split(b'\0')
        changed = [p.decode('utf-8') for p in changed if p]
        require(changed and all(p in (*DOCS, CORPUS) or p.startswith(EVIDENCE) for p in changed), 'non-metadata path changed')

        def evidence_tree(label, revision):
            rows = {}
            for item in git(label, 'ls-tree', '-r', '-z', revision, '--', EVIDENCE).split(b'\0'):
                if item:
                    header, path = item.split(b'\t', 1)
                    rows[path.decode('utf-8')] = header.decode('ascii').split()
            return rows

        old_evidence = evidence_tree('old-evidence-tree', BASE)
        new_evidence = evidence_tree('new-evidence-tree', args.head)
        for path, old in old_evidence.items():
            require(path in new_evidence, 'old evidence deleted: ' + path)
            require(new_evidence[path][:2] == old[:2] if path == EVIDENCE + 'README.md' else new_evidence[path] == old,
                    'old evidence blob/mode/type changed: ' + path)
        for path in new_evidence.keys() - old_evidence.keys():
            require(new_evidence[path][:2] == ['100644', 'blob'], 'new evidence is not a regular non-executable blob: ' + path)
        old_corpus = json.loads(git('old-corpus', 'show', BASE + ':' + CORPUS))
        new_corpus = json.loads(git('new-corpus', 'show', args.head + ':' + CORPUS))
        for i, path in enumerate(DOCS):
            blob = git('doc-pin-' + str(i), 'rev-parse', args.head + ':' + path).decode().strip()
            require(new_corpus['pinned_blobs'][path] == blob, 'documentation pin mismatch')
            new_corpus['pinned_blobs'][path] = old_corpus['pinned_blobs'][path]
        require(new_corpus == old_corpus, 'corpus changed beyond the two documentation pins')
        result.update(changed_paths=changed, prior_failed_observations_replaced=False,
                      runtime_proof_workflow_test_bytes_unchanged=True, metadata_scope_verified=True)
        save(out / 'metadata-scope.json', {'head': args.head, 'changed_paths': changed,
             'old_evidence_preserved_except_readme_content': True, 'corpus_only_two_documentation_pins': True})
        result['terminal_before_ff'] = terminal_guard()
        identity('before-ff', BASE, BASE_TREE)
        require(file_record(VERIFIER, VERIFY_SHA) == result['verifier_before'], 'verifier identity changed')
        result['fast_forward_attempted'] = True
        git('fast-forward-only', 'merge', '--ff-only', '--no-edit', args.head)
        result['source_after_ff'] = identity('after-ff', args.head)
        result['verifier_attempted'] = True
        run('frozen-metadata-verifier', [PYTHON, '-B', str(VERIFIER), '--repo', str(REPO),
                                       '--head', args.head, '--out', str(checks)], timeout=12600)
        check_pin, check_bytes = file_record(checks / 'summary.json', read=True)
        checked = json.loads(check_bytes)
        require(checked['status'] == 'PASS_METADATA_SOURCE_CHECKS_HOLD' and
                checked['publication_head'] == args.head and checked['executed_runtime_head'] == BASE and
                checked['runner_sha256_before'] == VERIFY_SHA and checked['runner_sha256_after'] == VERIFY_SHA and
                checked['source_receipts_equal'] is True and checked['source_negative_cases'] == 151 and
                checked['native_tests_executed'] is False and checked['prior_failed_observations_replaced'] is False and
                checked['whole_chain_pq_qualified'] is False and checked['production_activation'] is False,
                'verifier summary does not match the required scoped result')
        require(tuple(c['name'] for c in checked['commands']) == CHECK_NAMES and
                all(c['passed'] is True and c['attempts'] == 1 and c['exit_code'] == 0 and c['timed_out'] is False for c in checked['commands']),
                'verifier command roster incomplete')
        for name, count in (('corpus-negatives', 58), ('ci-source-negatives', 43), ('repository-negatives', 50)):
            require(next(c for c in checked['commands'] if c['name'] == name)['unittest_counts'] == [count], 'wrong negative test count')
        result['verification_summary'] = check_pin
        result['metadata_commands_passed'] = 13
        result['source_negative_cases_passed'] = 151
        result['status'] = 'IMPORTED_AND_SOURCE_VERIFIED_HOLD'
    except BaseException as e:
        result['status'] = 'FAILED_OR_INCOMPLETE'
        result['error'] = type(e).__name__ + ': ' + str(e)
    finally:
        try:
            actual = git('final-head', 'rev-parse', 'HEAD').decode().strip()
            result['actual_head_after'] = actual
            require(actual in (BASE, args.head), 'unexpected final HEAD')
            result['source_final'] = identity('final', actual, BASE_TREE if actual == BASE else None)
            source('source-final', actual)
            result['terminal_after'] = terminal_guard()
            result['bundle_after'] = file_record(args.bundle, args.bundle_sha256)
            result['verifier_after'] = file_record(VERIFIER, VERIFY_SHA)
            result['runner_after'] = file_record(Path(__file__).absolute())
            require(runner_before is not None and result['runner_after'] == runner_before, 'runner identity changed')
            require(result['bundle_after'] == result.get('bundle_before') and
                    result['verifier_after'] == result.get('verifier_before'), 'input identity changed')
            if result['status'] == 'IMPORTED_AND_SOURCE_VERIFIED_HOLD':
                require(actual == args.head, 'verified import did not retain Y')
                require(file_record(checks / 'summary.json') == result['verification_summary'], 'verification receipt changed')
        except BaseException as e:
            result['status'] = 'FAILED_OR_INCOMPLETE'
            result['final_guard_error'] = type(e).__name__ + ': ' + str(e)
        result['finished_unix'] = time.time()
        save(out / 'summary.json', result)
        print(json.dumps({k: result.get(k) for k in ('status', 'head_requested', 'actual_head_after',
              'objects_import_attempted', 'fast_forward_attempted', 'verifier_attempted', 'error', 'final_guard_error')}), flush=True)
    return 0 if result['status'] == 'IMPORTED_AND_SOURCE_VERIFIED_HOLD' else 1


if __name__ == '__main__':
    raise SystemExit(main())
