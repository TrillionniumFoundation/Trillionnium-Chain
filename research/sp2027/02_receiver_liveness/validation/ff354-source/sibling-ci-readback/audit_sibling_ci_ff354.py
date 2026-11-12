#!/usr/bin/env python3
"""Read exact failed CI logs and Git blobs; do not run or relax any QROM gate."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASE = '5b591754b426c6f88bea6d399fafcd77e31255d8'
PRIOR = '0bc51795a978494af1b4659712ecf78c290c1a88'
HEAD = 'ff35430d27eea56dd803e05aa6d48573e37ed4c9'
JOBS = [
    (43131136371, 130895273579, 'closure', 'head', 130876620011),
    (43131136371, 130895273690, 'closure', 'prospective-merge', 130876619595),
    (43131136548, 130895273873, 'implementation', 'prospective-merge', 130876622889),
    (43131136548, 130895274729, 'implementation', 'head', 130876623123),
]
PATHS = [
    'formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs',
    'trillionnium/crates/trnm-pon-node/src/consensus.rs',
    'config/pon/w1-qrom-implementation-v1.json',
    'scripts/w1_lifetime_ledger.py',
    'scripts/w1_qrom_implementation_audit.py',
    'scripts/ci/test_w1_lifetime_ledger.py',
    'scripts/ci/test_w1_qrom_implementation_audit.py',
    '.github/workflows/pon-w1-qrom-closure.yml',
    '.github/workflows/pon-w1-qrom-implementation.yml',
]
EXCEPTIONS = re.compile(r'(?:AuditError|LedgerError|AssertionError|ValueError|RuntimeError):')
STAMP = re.compile(r'^\ufeff?\d{4}-\d\d-\d\dT[^ ]+Z ')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def log_summary(path):
    raw = path.read_bytes()
    lines = raw.decode().splitlines()
    start = next(i for i, line in enumerate(lines) if 'Traceback (most recent call last):' in line)
    end = next(i for i in range(start + 1, len(lines)) if EXCEPTIONS.search(lines[i]))
    exceptions = sorted({STAMP.sub('', line) for line in lines if EXCEPTIONS.search(line)})
    return {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw),
            'first_traceback_line': start + 1, 'first_traceback': '\n'.join(lines[start:end + 1]),
            'first_cause': STAMP.sub('', lines[end]), 'observed_exception_messages': exceptions,
            'exception_selector': EXCEPTIONS.pattern}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--prior-logs', type=Path, required=True)
    parser.add_argument('--prior-audit', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists()
    prior_bytes = args.prior_audit.read_bytes()
    prior_audit = json.loads(prior_bytes)
    assert prior_audit['head'] == PRIOR and prior_audit['common_base'] == BASE
    old_rows = {row['job_id']: row for row in prior_audit['jobs']}
    env = os.environ.copy()
    env['GIT_NO_LAZY_FETCH'] = '1'
    env['GIT_TERMINAL_PROMPT'] = '0'

    def git(*argv):
        return subprocess.check_output(['git', '-C', str(args.repo), *argv], env=env)

    trees = {commit: git('rev-parse', commit + '^{tree}').decode().strip() for commit in [BASE, PRIOR, HEAD]}
    bodies, files = {}, []
    for path in PATHS:
        observations = {}
        for commit in [BASE, PRIOR, HEAD]:
            raw = git('show', commit + ':' + path)
            bodies[(commit, path)] = raw
            observations[commit] = {'bytes': len(raw), 'sha256': sha(raw),
                'git_blob_oid': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        equal = bodies[(BASE, path)] == bodies[(PRIOR, path)] == bodies[(HEAD, path)]
        assert equal, 'selected predicate source changed: ' + path
        files.append({'path': path, 'byte_equal_at_all_three_commits': equal, 'observations': observations})
    contract = json.loads(bodies[(HEAD, 'config/pon/w1-qrom-implementation-v1.json')])
    main_path = PATHS[0]
    main_pin = next(row for row in contract['project_files'] if row['path'] == main_path)
    assert len(bodies[(HEAD, main_path)]) > main_pin['bytes']
    ledger = ast.parse(bodies[(HEAD, 'scripts/w1_lifetime_ledger.py')])
    pins = next(ast.literal_eval(node.value) for node in ledger.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'SOURCE_PINS' for target in node.targets))
    consensus_path = PATHS[1]
    assert sha(bodies[(HEAD, consensus_path)]) != pins[consensus_path]
    jobs = []
    for run, job, kind, checkout, old_job in JOBS:
        current = log_summary(args.current / f'qrom-job-{job}.decoded.log')
        old = log_summary(args.prior_logs / f'qrom-job-{old_job}.decoded.log')
        prior_row = old_rows[old_job]
        assert old['sha256'] == prior_row['decoded_log_sha256'] and old['bytes'] == prior_row['decoded_log_bytes']
        assert old['first_cause'] == prior_row['cause']
        run_file, job_file = args.current / f'run-{run}.json', args.current / f'jobs-{run}.json'
        run_data, job_data = json.loads(run_file.read_bytes()), json.loads(job_file.read_bytes())
        assert run_data['head_sha'] == HEAD and run_data['conclusion'] == 'failure'
        observed_job = next(row for row in job_data['jobs'] if row['id'] == job)
        assert observed_job['conclusion'] == 'failure' and checkout in observed_job['name']
        before_after = [row for row in observed_job['steps'] if 'source' in row['name'].lower()
                        and ('before execution' in row['name'].lower() or 'after execution' in row['name'].lower())]
        assert len(before_after) == 2 and all(row['conclusion'] == 'success' for row in before_after)
        jobs.append({'run_id': run, 'job_id': job, 'kind': kind, 'checkout_kind': checkout,
            'url': f'https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/{run}/job/{job}',
            'job_conclusion': observed_job['conclusion'], 'first_failed_step': next(row for row in observed_job['steps'] if row['conclusion'] == 'failure'),
            'all_failed_steps': [row for row in observed_job['steps'] if row['conclusion'] == 'failure'],
            'source_verification_steps': before_after, 'current_log': current, 'prior_log': old,
            'same_first_failure_as_prior_original': current['first_cause'] == old['first_cause'],
            'same_observed_exception_set_as_prior_original': current['observed_exception_messages'] == old['observed_exception_messages'],
            'new_observed_exception_messages': sorted(set(current['observed_exception_messages']) - set(old['observed_exception_messages'])),
            'metadata': {run_file.name: sha(run_file.read_bytes()), job_file.name: sha(job_file.read_bytes())}})
    assert all(row['same_first_failure_as_prior_original'] for row in jobs)
    assert all(row['same_observed_exception_set_as_prior_original'] for row in jobs)
    result = {'schema': 'sp27-02-ff354-sibling-ci-readback-v1',
        'common_base': BASE, 'previously_audited_head': PRIOR, 'execution_head': HEAD, 'git_trees': trees,
        'jobs': jobs, 'source_files': files,
        'implementation_first_predicate': {'path': main_path, 'actual_bytes': len(bodies[(HEAD, main_path)]),
            'contract_pin': main_pin, 'actual_sha256': sha(bodies[(HEAD, main_path)]),
            'failure': 'actual length exceeds unchanged contract bound before subsequent pinned-input comparison'},
        'closure_first_predicate': {'path': consensus_path, 'actual_sha256': sha(bodies[(HEAD, consensus_path)]),
            'unchanged_source_pin': pins[consensus_path], 'failure': 'actual source SHA-256 differs from unchanged SOURCE_PINS entry'},
        'prior_audit_sha256': sha(prior_bytes), 'prior_audit_file': str(args.prior_audit),
        'classification': 'The same first failure predicates and observed exception-message sets recur in both head and prospective-merge jobs; all nine selected target/contract/helper/test/workflow files are byte-identical at the common base, prior head and execution head.',
        'comparison_boundary': 'Git blob equality covers BASE, prior 0bc and execution ff354; prospective-merge source checks are the actual saved job steps and original log outcomes. This record does not assert unobserved later test outcomes or that every other CI is green.',
        'native_experiments_executed': 0, 'base_ci_rerun': False, 'pins_or_gates_changed': False,
        'unrelated_systems_repaired': False, 'implicit_git_lazy_fetch_disabled': True,
        'other_ff354_workflows': 'NOT_AUDITED_IN_THIS_RECORD; may remain queued/running/failed',
        'audit_script_sha256': sha(Path(__file__).read_bytes())}
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    args.out.chmod(0o444)
    print(json.dumps({'out': str(args.out), 'sha256': sha(args.out.read_bytes()),
        'jobs': len(jobs), 'source_files_equal': len(files), 'same_first_failure': True,
        'same_observed_exception_set': True, 'new_observed_exception_messages': []}, sort_keys=True))


if __name__ == '__main__':
    main()
