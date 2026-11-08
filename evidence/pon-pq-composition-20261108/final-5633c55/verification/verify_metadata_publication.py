#!/usr/bin/env python3
"""Verify an evidence/documentation-only child without relabeling native runs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

BASE = '5633c55219c01c689f670c2ca35d122e39f3f791'
DOCS = (
    'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md',
    'docs/security/PQ_COMPOSITION_20261108.md',
)
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
EVIDENCE = 'evidence/pon-pq-composition-20261108/'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    require(re.fullmatch('[0-9a-f]{40}', args.head), 'full head required')
    require(not out.is_relative_to(repo) and not out.exists(), 'fresh external output required')
    out.mkdir(parents=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    results = []
    summary = {'schema': 'trnm-metadata-publication-verification-v1',
               'executed_runtime_head': BASE, 'publication_head': args.head,
               'runner_sha256_before': runner_hash, 'commands': results,
               'native_tests_executed': False, 'prior_failed_observations_replaced': None,
               'whole_chain_pq_qualified': False, 'production_activation': False,
               'status': 'INCOMPLETE'}

    def save(path, value):
        with path.open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')

    def command(name, argv, expected_tests=None):
        directory = out / name
        directory.mkdir()
        begin = time.monotonic()
        row = {'name': name, 'argv': argv, 'cwd': str(repo),
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'attempts': 1, 'timed_out': False}
        with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
            try:
                completed = subprocess.run(argv, cwd=repo, env=env, stdout=stdout,
                                           stderr=stderr, timeout=900)
                row['exit_code'] = completed.returncode
            except subprocess.TimeoutExpired:
                row.update(exit_code=None, timed_out=True)
        data = (directory / 'stdout.log').read_bytes()
        error = (directory / 'stderr.log').read_bytes()
        combined = (data + error).decode('utf-8', 'replace')
        counts = ([int(item) for item in re.findall(r'Ran (\d+) tests? in ', combined)]
                  if expected_tests is not None else [])
        row.update(elapsed_seconds=round(time.monotonic() - begin, 3),
                   stdout_sha256=hashlib.sha256(data).hexdigest(),
                   stderr_sha256=hashlib.sha256(error).hexdigest(), unittest_counts=counts,
                   expected_unittest_count=expected_tests)
        row['passed'] = (row['exit_code'] == 0 and not row['timed_out'] and
                         (expected_tests is None or (counts == [expected_tests] and
                          re.search(r'\nOK\s*\Z', combined) is not None)))
        save(directory / 'receipt.json', row)
        results.append(row)
        print(json.dumps({k: row[k] for k in ('name', 'exit_code', 'passed', 'unittest_counts')}), flush=True)
        return data.decode('utf-8')

    def git(*argv):
        return subprocess.check_output(['git', *argv], cwd=repo, env=env)

    try:
        command('preflight', ['bash', 'scripts/project-preflight.sh'])
        require(results[-1]['passed'], 'preflight failed')
        require(git('rev-parse', 'HEAD').decode().strip() == args.head, 'wrong HEAD')
        require(git('status', '--porcelain=v1', '--untracked-files=all') == b'', 'dirty source')
        require(git('rev-list', '--parents', '-n', '1', args.head).decode().split() == [args.head, BASE],
                'publication must be a direct evidence child of the executed candidate')
        changed = git('diff', '--no-renames', '--name-only', BASE, args.head).decode().splitlines()
        require(bool(changed), 'empty publication')
        require(all(path in (*DOCS, CORPUS) or path.startswith(EVIDENCE) for path in changed),
                'runtime, proof, tests, workflow or undeclared configuration changed')
        def evidence_tree(revision):
            rows = {}
            for record in git('ls-tree', '-r', '-z', revision, '--', EVIDENCE).split(b'\0'):
                if record:
                    header, path = record.split(b'\t', 1)
                    rows[path.decode('utf-8')] = header.decode('ascii').split()
            return rows
        old_evidence, new_evidence = evidence_tree(BASE), evidence_tree(args.head)
        for path, identity in old_evidence.items():
            require(path in new_evidence, 'old evidence deleted: ' + path)
            if path == EVIDENCE + 'README.md':
                require(new_evidence[path][:2] == identity[:2], 'README mode/type changed')
            else:
                require(new_evidence[path] == identity, 'old raw evidence blob/mode changed: ' + path)
        for path in new_evidence.keys() - old_evidence.keys():
            require(new_evidence[path][:2] == ['100644', 'blob'],
                    'new evidence must be a regular non-executable Git blob: ' + path)
        old = json.loads(git('show', BASE + ':' + CORPUS))
        new = json.loads(git('show', args.head + ':' + CORPUS))
        for path in DOCS:
            actual = git('rev-parse', args.head + ':' + path).decode().strip()
            require(new['pinned_blobs'][path] == actual, 'documentation pin mismatch: ' + path)
            new['pinned_blobs'][path] = old['pinned_blobs'][path]
        require(new == old, 'corpus changed beyond the two documentation pins')
        summary.update(changed_paths=changed, runtime_proof_workflow_test_bytes_unchanged=True,
                       prior_evidence_blobs_and_modes_preserved_except_readme=True,
                       prior_failed_observations_replaced=False,
                       corpus_changes_are_two_documentation_pins=True)
        save(out / 'metadata-scope.json', {k: v for k, v in summary.items() if k != 'commands'})
        source = [sys.executable, '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                  '--expected-head', args.head]
        before = command('source-before', source)
        require(results[-1]['passed'], 'initial raw-source identity check failed')
        checks = [
            ('corpus', 'scripts/ci/check_pq_research_integration.py', None),
            ('corpus-negatives', 'scripts/ci/test_pq_research_integration.py', 58),
            ('lifetime', 'scripts/ci/pq_lifetime_budget.py', None),
            ('authority-effects', 'scripts/ci/pq_authority_effect_register.py', None),
            ('authority-traces', 'scripts/ci/pq_authority_trace.py', None),
            ('claim-guard', 'scripts/ci/pq_chain_claim_guard.py', None),
            ('ci-source-negatives', 'scripts/ci/test_ci_source_integrity.py', 43),
            ('repository-markdown', 'scripts/ci/check_repository.py', None),
            ('repository-negatives', 'scripts/ci/test_repository.py', 50),
        ]
        for name, path, expected_tests in checks:
            command(name, [sys.executable, '-B', path], expected_tests=expected_tests)
        command('source-inventory', [sys.executable, '-B',
                                    'scripts/refresh_distributed_source_inventory.py', '--check'])
        after = command('source-after', source)
        require(git('status', '--porcelain=v1', '--untracked-files=all') == b'', 'source mutated')
        after_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        summary.update(source_receipts_equal=before == after,
                       runner_sha256_after=after_hash,
                       source_negative_cases=sum(sum(row['unittest_counts']) for row in results))
        require(before == after and runner_hash == after_hash, 'source or runner identity changed')
        require(summary['source_negative_cases'] == 151, 'incomplete source-negative test roster')
        summary['status'] = ('PASS_METADATA_SOURCE_CHECKS_HOLD'
                             if all(row['passed'] for row in results) else 'FAILED_OR_BLOCKED')
    except Exception as error:
        summary.update(status='FAILED_OR_BLOCKED', error=type(error).__name__ + ': ' + str(error))
    finally:
        summary['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(out / 'summary.json', summary)
        print(json.dumps({k: v for k, v in summary.items() if k not in ('commands', 'changed_paths')}), flush=True)
    return 0 if summary['status'] == 'PASS_METADATA_SOURCE_CHECKS_HOLD' else 1


if __name__ == '__main__':
    raise SystemExit(main())
