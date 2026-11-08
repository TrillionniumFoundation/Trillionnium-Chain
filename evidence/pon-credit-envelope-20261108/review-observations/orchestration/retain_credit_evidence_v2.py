#!/usr/bin/env python3
"""Retain two exact-source runs and public provider receipts; never push.

All inputs are read and checked before the first worktree write. This collector
accepts only the completed run2 roster on its still-clean tested head. It keeps
run1's two failures unchanged and does not attribute its 50/16 historical tests
to the repaired head. Provider inputs are a literal public-file allowlist.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zlib

sys.dont_write_bytecode = True

ROOT = Path('/home/qian-qi/chain-credit-envelope-20261108-f7e62')
RUN1 = Path('/home/qian-qi/credit-envelope-f7e62-run1')
RUN2 = Path('/home/qian-qi/credit-envelope-f7e62-run2')
FINAL = Path('/home/qian-qi/credit-envelope-f7e62-final')
EVIDENCE_REL = 'evidence/pon-credit-envelope-20261108'
EVIDENCE = ROOT / EVIDENCE_REL
INITIAL = '57511355b9dfb1fc02c90eb0713fd8e95263a662'
BASE = '8d5389748873dad6e296d17f2ff20483b5afa5bc'
BRANCH = 'fix/chain-credit-envelope-20261108-f7e62'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
MISSING_PATH = 'trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs'
PROVIDER1 = Path('/home/qian-qi/credit-envelope-f7e62-provider')
PROVIDER2 = Path('/home/qian-qi/credit-envelope-f7e62-provider2')
STATUS1 = Path('/home/qian-qi/credit-envelope-f7e62-runtime-initial-status.json')
STATUS2 = Path('/home/qian-qi/credit-envelope-f7e62-runtime-final-status.json')
PROVIDER_STATUS1 = Path('/home/qian-qi/credit-envelope-f7e62-provider-initial-status.json')
ARCHIVE_SHA = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
ARCHIVE_BYTES = 53279637
ORIGINAL_DRIVER_SHA = 'ce05862e66ab72bd54f7017283fa987ad86aff41cc1bfee3828b825ed2d2587a'
MAX_TREE_BYTES = 100 * 1024 * 1024
MAX_REVIEW_BYTES = 32 * 1024 * 1024
INITIAL_PREFIX = 'runtime-initial-57511355b'
CURRENT_PREFIX = 'runtime-current'
MARKER = '## Completed runtime observations: initial failures and repaired source'
ORIGINAL_NAMES = [
    'preflight', 'finite-math', 'candidate-clock', 'restricted-oracle',
    'source-integrity', 'ci-contract', 'repository-negative',
    'project-boundary-negative', 'repository-check', 'inventory-check',
    'cargo-graph', 'cargo-graph-all-features', 'rust-format', 'rust-clippy',
    'retained-native-work',
]
HISTORICAL_COUNTS = {'repository-negative': 50, 'project-boundary-negative': 16}
UNITTEST_COUNTS = {'candidate-clock': 6, 'restricted-oracle': 12,
                   'source-integrity': 43, 'ci-contract': 107, **HISTORICAL_COUNTS}
EXACT_TESTS = {
    'distributed-source-scope': 'tests::source_scope_and_campaign_bounds_reject',
    'distributed-resume-identity':
        'tests::resume_requires_exact_source_config_identity_and_exclusive_owner',
}
CURRENT_NAMES = [name for name in ORIGINAL_NAMES if name not in HISTORICAL_COUNTS] + list(EXACT_TESTS)
PUBLIC_PROVIDER_FILES = (
    'observations/pq-provider/build-and-smoke.log',
    'observations/pq-provider/provider.json',
    'transport-summary.json', 'archive-verification.json', 'setup-result.json',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse_json(data):
    def reject_constant(value):
        raise ValueError('nonfinite JSON value: ' + value)
    return json.loads(data, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant)


def checked_file(path, maximum=MAX_TREE_BYTES):
    require(path.is_absolute() and path.resolve(strict=True) == path,
            'noncanonical or symlink input: ' + str(path))
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
            'nonregular or oversized input: ' + str(path))
    data = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    require(identity(before) == identity(after) and len(data) == before.st_size,
            'input changed while being read: ' + str(path))
    return data


def relative_name(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value)
            and len(value) <= 512, 'invalid relative receipt path')
    parts = value.split('/')
    require(all(part not in ('.', '..', '.git', 'runner', 'smoke') for part in parts)
            and not PurePosixPath(value).is_absolute(), 'forbidden receipt path: ' + value)
    require(PurePosixPath(value).suffix.lower() not in ('.pem', '.key', '.p12', '.pfx'),
            'key material is not a public receipt: ' + value)
    return value


def public_bytes(name, data):
    relative_name(name)
    require(not re.search(rb'-----BEGIN [A-Z0-9 ]+-----', data),
            'PEM material in proposed public receipt: ' + name)
    return data


def tree_snapshot(directory):
    require(directory.is_dir() and directory.resolve(strict=True) == directory,
            'noncanonical observation directory: ' + str(directory))
    files, total = {}, 0
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'symlink in observation tree: ' + str(path))
        mode = path.stat(follow_symlinks=False).st_mode
        if stat.S_ISDIR(mode):
            require(path.resolve(strict=True) == path, 'noncanonical observation directory')
            continue
        require(stat.S_ISREG(mode), 'special file in observation tree: ' + str(path))
        name = relative_name(path.relative_to(directory).as_posix())
        data = public_bytes(name, checked_file(path))
        total += len(data)
        require(total <= MAX_TREE_BYTES and len(files) < 10000, 'observation tree exceeds bound')
        files[name] = data
    require(files, 'empty observation tree')
    return files


def document(files, name):
    require(name in files, 'missing receipt: ' + name)
    value = parse_json(files[name])
    require(type(value) is dict, 'receipt must be an object: ' + name)
    return value


def require_scope(value):
    require(value.get('overall_security_qualification') == 'HOLD'
            and value.get('production_activation') is False,
            'security qualification must remain HOLD')


def validate_status(raw, state, exit_code):
    result = parse_json(raw)
    require(type(result) is dict and result.get('state') == state
            and type(result.get('exit_code')) is int and result['exit_code'] == exit_code,
            'runtime terminal state or exit code mismatch')
    for field in ('output_complete', 'output_durable', 'terminal_publication_confirmed'):
        require(result.get(field) is True, 'runtime output is not durable and complete: ' + field)
    require(result.get('timed_out') is False
            and result.get('cancelled') is (state == 'cancelled')
            and type(result.get('job_id')) is str and result['job_id'],
            'unexpected runtime cancellation, timeout, or identity')
    for stream in ('stdout', 'stderr'):
        require(result.get('log_synced', {}).get(stream) is True
                and result.get('log_truncated', {}).get(stream) is False
                and result.get('log_errors', {}).get(stream) is None,
                'incomplete runtime stream status: ' + stream)
        counts = result.get('log_bytes', {}).get(stream, {})
        require(type(counts.get('seen')) is int and type(counts.get('stored')) is int
                and counts['seen'] == counts['stored'] >= 0, 'runtime byte accounting mismatch')
    return result


def validate_stage(files, stage, expected_pass, expected_argv):
    name = stage.get('stage')
    require(type(name) is str and re.fullmatch(r'[a-z][a-z0-9-]*', name), 'invalid stage name')
    require(document(files, name + '.stage.json') == stage, 'summary/stage receipt mismatch: ' + name)
    require(stage.get('passed') is expected_pass and type(stage.get('exit_code')) is int
            and (stage['exit_code'] == 0) is expected_pass
            and stage.get('exception') is None and 'validation_error' not in stage,
            'stage terminal result mismatch: ' + name)
    require(stage.get('cwd') == str(ROOT) and stage.get('argv') == expected_argv,
            'stage command identity mismatch: ' + name)
    for stream in ('stdout', 'stderr'):
        filename = name + '.' + stream + '.log'
        require(stage.get(stream) == filename and filename in files
                and stage.get(stream + '_sha256') == digest(files[filename]),
                'stage raw-log digest mismatch: ' + name + '/' + stream)
    if not expected_pass:
        return
    stdout, stderr = (files[name + '.' + stream + '.log'].decode('utf-8')
                      for stream in ('stdout', 'stderr'))
    if name in UNITTEST_COUNTS:
        combined = stdout + '\n' + stderr
        runs = re.findall(r'^Ran ([0-9]+) tests? in .+$', combined, re.M)
        terminal = re.search(r'(?:\A|\n)Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s\n\nOK\s*\Z', combined)
        count = UNITTEST_COUNTS[name]
        require(runs == [str(count)] and terminal is not None and terminal.group(1) == str(count)
                and stage.get('unittest_terminal_receipt_valid') is True
                and type(stage.get('test_methods')) is int and stage['test_methods'] == count,
                'wrong or nonterminal unittest receipt: ' + name)
    if name == 'finite-math':
        completion = document(files, 'finite-math/completion.json')
        require(stage.get('completion') == completion
                and completion.get('schema') == 'pon-credit-envelope-completion-v1'
                and completion.get('finite_math_checks') == 'PASS'
                and type(completion.get('distinct_named_tests_passed')) is int
                and completion['distinct_named_tests_passed'] == 77
                and completion.get('source_bytes_unchanged') is True
                and completion.get('overall') == 'HOLD'
                and completion.get('production_activation') is False,
                'finite-math completion is not the pinned 77-method pass')
    if name.startswith('cargo-graph'):
        members = parse_json(stdout)['workspace_members']
        require(type(members) is list and len(members) == len(set(members)) == 26
                and type(stage.get('workspace_members')) is int and stage['workspace_members'] == 26,
                'Cargo graph package count mismatch')
    if name == 'retained-native-work' or name in EXACT_TESTS:
        result_lines = [line for line in stdout.splitlines() if line.startswith('test result:')]
        matches = re.findall(r'^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; '
                             r'([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9]+(?:\.[0-9]+)?s$', stdout, re.M)
        count = 1 if name in EXACT_TESTS else 135
        require(len(matches) == len(result_lines) == 1
                and stdout.rstrip().endswith(result_lines[0])
                and tuple(map(int, matches[0][:4])) == (count, 0, 0, 0),
                'native test result mismatch: ' + name)
        if 'native_test_counts' in stage:
            expected = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
                                map(int, matches[0])))
            require(stage['native_test_counts'] == expected
                    and all(type(value) is int for value in stage['native_test_counts'].values()),
                    'native count fields differ from raw output')
        else:
            require(stage.get('native_test_results') == [list(matches[0][:3])],
                    'initial native count fields differ from raw output')
        if name in EXACT_TESTS:
            line = 'test ' + EXACT_TESTS[name] + ' ... ok'
            require(stage.get('exact_test_name') == EXACT_TESTS[name]
                    and stage.get('exact_test_line') == line
                    and re.findall(r'^running ([0-9]+) tests?$', stdout, re.M) == ['1']
                    and [row for row in stdout.splitlines() if row.startswith('test ')
                         and not row.startswith('test result:')] == [line],
                    'exact distributed test was not executed once: ' + name)


def validate_run(files, directory, head, tree, commands, *, current):
    summary = document(files, 'validation-summary.json')
    require_scope(summary)
    require(summary.get('schema') == 'pon-credit-envelope-runtime-validation-v' + ('2' if current else '1')
            and summary.get('source_commit') == head and summary.get('source_tree') == tree
            and summary.get('integration_base') == BASE and summary.get('source_kind') == 'head'
            and summary.get('prospective_merge_executed_here') is False
            and summary.get('complete_source_receipts_identical') is True
            and summary.get('all_stages_passed') is current and 'driver_error' not in summary,
            'runtime summary source or completion mismatch')
    names = ['source-before'] + [row[0] for row in commands] + ['source-after']
    stages = summary.get('stages')
    require(type(stages) is list and len(stages) == 17
            and all(type(row) is dict for row in stages)
            and [row.get('stage') for row in stages] == names, 'runtime stage roster mismatch')
    if current:
        require(summary.get('expected_stage_names') == names
                and summary.get('stage_roster_complete') is True
                and summary.get('selected_provider_unchanged') is True
                and summary.get('repair_parent') == INITIAL, 'current completion guards are incomplete')
    expected_commands = {name: [argument.replace('@OUT@', str(directory)) for argument in arguments]
                         for name, arguments in commands}
    for name in ('source-before', 'source-after'):
        expected_commands[name] = ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                   '--expected-head', head, '--output', str(directory / (name + '.json'))]
    failures = set() if current else {'inventory-check', 'rust-clippy'}
    for stage in stages:
        validate_stage(files, stage, stage['stage'] not in failures, expected_commands[stage['stage']])
    require(files['source-before.json'] == files['source-after.json'], 'source receipts changed during execution')
    for name in ('source-before', 'source-after'):
        receipt = document(files, name + '.json')
        require(receipt.get('schema') == 'trnm-ci-source-v1' and receipt.get('kind') == 'head'
                and receipt.get('tested_commit') == head and receipt.get('tested_tree') == tree
                and receipt.get('candidate') == head and receipt.get('base') is None
                and receipt.get('prospective_merge') is None
                and receipt.get('tracked_worktree_verified') is True
                and type(receipt.get('tracked_entries')) is int and receipt['tracked_entries'] > 0
                and type(receipt.get('tracked_bytes')) is int and receipt['tracked_bytes'] >= 0
                and files[name + '.stdout.log'] == files[name + '.json'],
                'source receipt does not bind the exact complete worktree')
        if current:
            stage = next(row for row in stages if row['stage'] == name)
            require(stage.get('source_receipt_sha256') == digest(files[name + '.json']),
                    'complete-source receipt digest mismatch')
    source = document(files, 'source-commit.json')
    require(source.get('commit') == head and source.get('tree') == tree and source.get('base') == BASE,
            'source-commit receipt mismatch')
    return summary


def read_review(packet, expected_sha):
    require(re.fullmatch(r'[0-9a-f]{64}', expected_sha), 'review digest must be lowercase SHA-256')
    packed = checked_file(packet, MAX_REVIEW_BYTES)
    require(digest(packed) == expected_sha, 'review packet SHA-256 mismatch')
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(packed, MAX_REVIEW_BYTES + 1)
    require(len(raw) <= MAX_REVIEW_BYTES and decompressor.eof
            and not decompressor.unused_data and not decompressor.unconsumed_tail,
            'oversized, incomplete, or concatenated review packet')
    review = parse_json(raw)
    require(type(review) is dict and review.get('schema') == 'pon-credit-review-evidence-transfer-v1'
            and type(review.get('files')) is list and 1 <= len(review['files']) <= 1000,
            'unexpected review packet schema or file list')
    files = {}
    for item in review['files']:
        require(type(item) is dict and set(item) == {'path', 'sha256', 'content'}, 'review file fields mismatch')
        name = relative_name(item['path'])
        require(name not in files and type(item['content']) is str
                and type(item['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', item['sha256']),
                'duplicate or malformed review file')
        data = public_bytes(name, item['content'].encode('utf-8'))
        require(digest(data) == item['sha256'], 'review file SHA-256 mismatch: ' + name)
        files[name] = data
    for name in files:
        require(not any(parent.as_posix() in files for parent in PurePosixPath(name).parents
                        if parent.as_posix() != '.'), 'review file/directory collision')
    required = {'development-ci-merge/final-merge-summary.json', 'development-ci-merge/latest-ci-contract.log',
                'development-ci-merge/patch-validation.json', 'orchestration/apply_validate_credit.py',
                'orchestration/repair_validate_credit.py', 'orchestration/validation-spec.json'}
    require(required <= set(files), 'review packet omits required original observations or executed drivers')
    return files


def result_detail(stage):
    if stage.get('test_methods') is not None:
        return str(stage['test_methods']) + ' named methods'
    if stage['stage'] == 'finite-math':
        return '77 pinned distinct methods; retained reports verified'
    if stage.get('workspace_members') is not None:
        return str(stage['workspace_members']) + ' packages; locked and offline'
    if stage.get('native_test_counts'):
        return str(stage['native_test_counts']['passed']) + ' passed; 0 failed; 0 ignored'
    if stage.get('native_test_results'):
        return str(stage['native_test_results'][0][0]) + ' passed; 0 failed; 0 ignored'
    return 'Exit ' + str(stage['exit_code']) + '; original stdout/stderr retained'


def table(summary):
    lines = ['| Exact-source check | Result | Observed detail |', '| --- | --- | --- |']
    for stage in summary['stages']:
        lines.append('| ' + stage['stage'] + ' | ' + ('PASS' if stage['passed'] else 'FAIL')
                     + ' | ' + result_detail(stage) + ' |')
    return '\n'.join(lines)


def readme_append(initial_summary, current_summary, source_receipt):
    head, tree = current_summary['source_commit'], current_summary['source_tree']
    return f'''

{MARKER}

Current tested source: `{head}`. Current tested tree: `{tree}`.
Initial source: `{INITIAL}`; initial tree: `{initial_summary['source_tree']}`.
Both descend from integration base `{BASE}`. The repaired source is the direct
child of the initial source and changes only the generated native inventory.

The [current complete execution](runtime-current/validation-summary.json) has
**17/17 stages passed**, including complete-source guards before and after,
13 repeated original stages and two individually named distributed-pipeline
tests. The [final job status](runtime-current/runtime-job-status.json) records
`succeeded`, exit 0, complete durable output and no timeout. The actual
[repair and validation driver](review-observations/orchestration/repair_validate_credit.py)
and [original driver](review-observations/orchestration/apply_validate_credit.py)
are retained with their exact reviewed bytes.

{table(current_summary)}

The current complete tracked-source receipts before and after are identical:
{source_receipt['tracked_entries']} entries and {source_receipt['tracked_bytes']} bytes.
The inner [77-method roster outcomes](runtime-current/finite-math/test-outcomes.json)
bind selected mathematical sources; the outer source receipts independently
bind the complete worktree. Neither source identity alone nor fixture loop
iterations count as executed named tests. The [credit readback](runtime-current/finite-math/credit-envelope-verified.json)
checks the credit inequalities or negative-cycle witness. The
[normalized-cost readback](runtime-current/finite-math/normalized-search-verified.json)
recomputes fixed-example arithmetic using the same implementation; it is not
an independent implementation, a W1 attack, or a resource lower bound.

### Initial run remains an observed failure

The [unaltered first summary](runtime-initial-57511355b/validation-summary.json)
retains all 17 initial stages, including **inventory-check FAIL** and
**rust-clippy FAIL**. Its [initial job status](runtime-initial-57511355b/runtime-job-status.json)
is `failed`, exit 1. All original raw files are copied byte for byte; the later
success does not rewrite either initial failure.

{table(initial_summary)}

The initial `repository-negative` 50-method and `project-boundary-negative`
16-method passes belong **only to `{INITIAL}`**. They were not rerun on the
repaired head. Their original outputs and explicit
[historical reuse declarations](runtime-current/validation-spec.json) remain
separate from the current 17-stage table.

The inventory failure came from one already-tracked integration source,
`{MISSING_PATH}`, missing from the generated inventory. The
[repair record](runtime-current/inventory-repair.json) and
[exact seven-line diff](runtime-current/inventory-repair.diff) retain the cause,
unchanged generator, matching ripgrep/Git enumeration, seven added lines and
zero removals. This second source commit only repairs that generated inventory;
it changes no miner or consensus logic.

Initial all-feature Clippy reached E0599 for `PKey::private_key_from_seed`
without the repository-pinned provider environment. The original diagnostics
in `pq_account_native.rs` and its included `pq_account_owner.rs` remain in
[initial Clippy stderr](runtime-initial-57511355b/rust-clippy.stderr.log).
The later run explicitly binds the original OpenSSL 3.5.9 preparation receipt
and native artifacts before and after execution. This is not a claim that the
inventory caused the Clippy failure or that all post-quantum behavior is qualified.

### Provider preparation and cancelled transport

The [successful original-script receipt](provider-current/observations/pq-provider/provider.json)
and [public build log](provider-current/observations/pq-provider/build-and-smoke.log)
retain the fixed OpenSSL 3.5.9 preparation. The official release asset is
{ARCHIVE_BYTES} bytes and SHA-256 `{ARCHIVE_SHA}`. Thirteen HTTP range parts were
assembled and the complete original pin was checked; the original preparation
script checked its copied archive again. The
[transport summary](provider-current/transport-summary.json),
[complete archive check](provider-current/archive-verification.json) and
[setup result](provider-current/setup-result.json) retain these separate steps.
No dependency version or source pin was changed. The
[selected provider before](runtime-current/selected-provider.json) and
[after](runtime-current/selected-provider-after.json) are identical.

The earlier provider download was **CANCELLED**, exit -15, while downloading.
Its [public log](provider-initial-cancelled/build-and-smoke.log) and
[explicit cancellation status](provider-initial-cancelled/runtime-job-status.json)
are retained separately. It is not a preparation or smoke-test pass.
Only the named public provider receipts and logs are retained. No runner tree,
smoke directory, PEM, private key, installed library, executable, or source
archive is copied into this evidence packet.

### Earlier development refusals also remain separate

The 109-method local prefix run had one failure for an inherited GSC2 mutation's
specific diagnostic. Its [recovered excerpt](runtime-initial-57511355b/development-observations/ci-prefix-initial-failure.log)
is explicitly an excerpt, not reconstructed full raw output. The guard order
was corrected; [subsequent complete local output](runtime-initial-57511355b/development-observations/ci-prefix-final.log)
is retained separately. The first remote apply check failed before source was
written; its [original refusal](runtime-initial-57511355b/development-observations/runtime-apply-initial-failure.json)
remains. Three-way integration retained existing integration CI lines, as
recorded in [patch validation](review-observations/development-ci-merge/patch-validation.json).

The intermediate mixed checkout's 107-method run had 104 successes and three
missing-file errors for `test_useful_cell_execution_v2.py`. Its
[complete original output](review-observations/development-ci-merge/latest-ci-contract.log)
and [scope summary](review-observations/development-ci-merge/final-merge-summary.json)
are preserved. The integrated 107-method successes in the runtime tables are
separate actual executions. Ten [footer-control fixtures](runtime-initial-57511355b/development-observations/retained-footer-controls.json)
remain fixtures and are not added to the 77-method roster.

### Qualification and publication boundary

Finite mathematics and the listed current engineering checks are **PASS**;
overall security qualification remains **HOLD**. Actual W1 minimum costs,
all-strategy and adaptive-portfolio bounds, mixed CP/CG/CQ, lifetime budgets,
hidden adversarial resources, original WAN acceptance and production activation
are not established by these observations.

This subsequent commit only retains evidence. Its complete non-evidence Git
entries must match the current tested source exactly. Publication and hosted
head/prospective-merge checks retain their own source identities; no prospective
merge execution is attributed to either runtime table. The
[receipt index](receipt-index.json) binds every retained raw file by size and
SHA-256 and preserves both terminal states.
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review-packet', type=Path, required=True)
    parser.add_argument('--review-sha256', required=True)
    args = parser.parse_args()
    overrides = {'PYTHONOPTIMIZE', 'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL',
                 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL'}
    env = {key: value for key, value in os.environ.items() if key not in overrides}
    env.update({'PYTHONDONTWRITEBYTECODE': '1', 'GIT_TERMINAL_PROMPT': '0',
                'GIT_NO_REPLACE_OBJECTS': '1'})

    def git_bytes(*arguments):
        return subprocess.check_output(['git', '--no-replace-objects', *arguments], cwd=ROOT, env=env)

    def git(*arguments):
        return git_bytes(*arguments).decode('utf-8').strip()

    def names(raw):
        return [item.decode('utf-8') for item in raw.split(b'\0') if item]

    def execute(arguments):
        result = subprocess.run(arguments, cwd=ROOT, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(result.stdout, end='', flush=True)
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr, flush=True)
        return result

    def clean():
        require(not git('status', '--porcelain', '--untracked-files=all', '--ignore-submodules=none'),
                'worktree or index is not clean')
        require(not git('for-each-ref', '--format=%(refname)', 'refs/replace/'), 'Git replacements are forbidden')
        require(not (ROOT / git('rev-parse', '--git-path', 'info/grafts')).exists(), 'Git grafts are forbidden')
        rows = git_bytes('ls-files', '-v', '-z').split(b'\0')
        require(not any(row and (row[:1].islower() or row[:1] == b'S') for row in rows),
                'index hides tracked worktree entries')

    def non_evidence(ref):
        return [entry for entry in git_bytes('ls-tree', '-r', '-z', ref).split(b'\0') if entry
                and not entry.split(b'\t', 1)[1].startswith(b'evidence/')]

    require(ROOT.resolve(strict=True) == ROOT and EVIDENCE.resolve(strict=True) == EVIDENCE,
            'source or evidence directory is not canonical')
    require(git('rev-parse', '--show-toplevel') == str(ROOT)
            and git('branch', '--show-current') == BRANCH
            and git('remote', 'get-url', 'origin') == ORIGIN, 'unexpected Git worktree identity')
    clean()
    first, current = tree_snapshot(RUN1), tree_snapshot(RUN2)
    current_summary = document(current, 'validation-summary.json')
    tested = current_summary.get('source_commit')
    require(type(tested) is str and re.fullmatch(r'[0-9a-f]{40}', tested)
            and git('rev-parse', 'HEAD') == tested, 'HEAD is not run2 tested source')
    tree, initial_tree = git('rev-parse', tested + '^{tree}'), git('rev-parse', INITIAL + '^{tree}')
    require(git('show', '-s', '--format=%P', tested) == INITIAL
            and names(git_bytes('diff', '--name-only', '-z', INITIAL, tested)) == [INVENTORY]
            and git('diff', '--numstat', INITIAL, tested, '--', INVENTORY) == '7\t0\t' + INVENTORY,
            'second source commit is not the sole seven-line generated inventory repair')
    added_block = ('    (\n' + f'        "{MISSING_PATH}",\n' + '        include_bytes!(concat!(\n'
                   + '            env!("CARGO_MANIFEST_DIR"),\n'
                   + f'            "/../../../{MISSING_PATH}"\n' + '        )),\n    ),\n').encode()
    inventory = git_bytes('show', tested + ':' + INVENTORY)
    require(inventory.count(added_block) == 1
            and inventory.replace(added_block, b'', 1) == git_bytes('show', INITIAL + ':' + INVENTORY),
            'inventory additions are not the exact pre-existing-source include entry')
    specification = document(current, 'validation-spec.json')
    require(specification.get('schema') == 'pon-credit-envelope-repair-validation-spec-v1',
            'unexpected repair validation specification')
    original, repaired = specification.get('original_stages'), specification.get('current_stages')
    for commands, roster in ((original, ORIGINAL_NAMES), (repaired, CURRENT_NAMES)):
        require(type(commands) is list and all(type(row) is list and len(row) == 2
                and type(row[1]) is list and row[1]
                and all(type(arg) is str and '\0' not in arg for arg in row[1]) for row in commands)
                and [row[0] for row in commands] == roster, 'validation command roster mismatch')
    expected_repaired = [row for row in original if row[0] not in HISTORICAL_COUNTS]
    expected_repaired += [[name, ['cargo', '+1.95.0', 'test', '--offline', '--locked',
                                  '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
                                  '--no-default-features', '--example', 'distributed_pipeline', test,
                                  '--', '--exact', '--test-threads=1']] for name, test in EXACT_TESTS.items()]
    require(repaired == expected_repaired, 'repair changed an original test command')
    initial_summary = validate_run(first, RUN1, INITIAL, initial_tree, original, current=False)
    current_summary = validate_run(current, RUN2, tested, tree, repaired, current=True)
    require(b'E0599' in first['rust-clippy.stderr.log']
            and b'private_key_from_seed' in first['rust-clippy.stderr.log'], 'initial Clippy cause differs')
    for name in ('ci-prefix-initial-failure.log', 'ci-prefix-final.log', 'retained-footer-controls.json',
                 'runtime-apply-initial-failure.json'):
        require('development-observations/' + name in first, 'initial development observation missing: ' + name)
    old_stages = {row['stage']: row for row in initial_summary['stages']}
    historical = current_summary.get('historical_stages_not_rerun_here')
    require(type(historical) is list and [row.get('stage') for row in historical] == list(HISTORICAL_COUNTS)
            and historical == specification.get('historical_stages_not_rerun_here'),
            'historical-only controls changed')
    for row in historical:
        name = row['stage']
        require(row.get('historical_source_commit') == INITIAL and row.get('historical_source_tree') == initial_tree
                and type(row.get('historical_test_methods')) is int
                and row['historical_test_methods'] == HISTORICAL_COUNTS[name]
                and row.get('rerun_on_repaired_head') is False and row.get('historical_receipt') == old_stages[name]
                and row.get('stage_receipt_sha256') == digest(first[name + '.stage.json']),
                'old 50/16 observations were changed or promoted to current results')
    repair = document(current, 'inventory-repair.json')
    require_scope(repair)
    require(repair.get('schema') == 'pon-credit-inventory-repair-v1'
            and repair.get('repair_result') == 'PASS' and repair.get('phase') == 'committed'
            and repair.get('source_commit') == tested and repair.get('source_tree') == tree
            and repair.get('repair_parent') == INITIAL and repair.get('omitted_path') == MISSING_PATH
            and repair.get('omitted_path_already_tracked_at_base') is True
            and repair.get('ripgrep_and_git_render_identical') is True
            and type(repair.get('added_lines')) is int and repair['added_lines'] == 7
            and type(repair.get('removed_lines')) is int and repair['removed_lines'] == 0
            and repair.get('actual_diff_sha256') == digest(current['inventory-repair.diff']),
            'inventory repair receipt does not identify the authorized single-entry change')
    status_raw = [checked_file(path, 65536) for path in (STATUS1, STATUS2, PROVIDER_STATUS1)]
    statuses = [validate_status(raw, state, code) for raw, state, code in
                zip(status_raw, ('failed', 'succeeded', 'cancelled'), (1, 0, -15))]
    require(len({row['job_id'] for row in statuses}) == 3, 'terminal statuses reuse a job identity')
    review = read_review(args.review_packet, args.review_sha256)
    require(digest(review['orchestration/apply_validate_credit.py']) == ORIGINAL_DRIVER_SHA
            == current_summary.get('adapted_driver_source_sha256')
            and digest(review['orchestration/repair_validate_credit.py']) == current_summary.get('repair_driver_sha256'),
            'reviewed driver bytes differ from executed driver identities')
    require(document(review, 'orchestration/validation-spec.json').get('stages') == original,
            'reviewed original validation commands differ')
    provider = {name: public_bytes(name, checked_file(PROVIDER2 / name)) for name in PUBLIC_PROVIDER_FILES}
    cancelled_log = public_bytes('build-and-smoke.log',
                                 checked_file(PROVIDER1 / 'observations/pq-provider/build-and-smoke.log'))
    receipt = document(provider, 'observations/pq-provider/provider.json')
    require(receipt.get('schema') == 'trnm-ci-pq-provider-v3'
            and receipt.get('result') == 'PREPARED_AND_SMOKE_VERIFIED' and receipt.get('last_stage') == 'complete'
            and receipt.get('version') == '3.5.9' and type(receipt.get('exit_code')) is int
            and receipt['exit_code'] == 0 and receipt.get('source_archive_sha256_expected') == ARCHIVE_SHA
            and receipt.get('source_digest_verified') is True and receipt.get('static_build') is True
            and receipt.get('ml_dsa_65_sign_verify_and_wrong_message_rejection') is True
            and receipt.get('native_rust_pq_tests_run_by_preparation') is False
            and receipt.get('whole_chain_quantum_security_qualified') is False
            and receipt.get('production_activation') is False, 'public provider receipt mismatch')
    transport, archive, setup = (document(provider, name) for name in
                                 ('transport-summary.json', 'archive-verification.json', 'setup-result.json'))
    require(transport.get('source_commit') == INITIAL and transport.get('expected_bytes') == ARCHIVE_BYTES
            and transport.get('expected_sha256') == ARCHIVE_SHA and transport.get('all_parts_complete') is True
            and type(transport.get('parts')) is list and len(transport['parts']) == 13
            and all(row.get('passed') is True for row in transport['parts'])
            and archive.get('bytes') == ARCHIVE_BYTES and archive.get('sha256') == ARCHIVE_SHA
            and archive.get('expected_sha256') == ARCHIVE_SHA and archive.get('passed') is True
            and setup.get('source_commit') == INITIAL and setup.get('source_unchanged') is True
            and setup.get('source_modified') is False and type(setup.get('exit_code')) is int and setup['exit_code'] == 0,
            'provider source transport, complete hash, or setup evidence mismatch')
    require(current['selected-provider.json'] == current['selected-provider-after.json']
            and digest(current['selected-provider.json']) == current_summary.get('selected_provider_receipt_sha256'),
            'selected provider changed during run2')
    selected = document(current, 'selected-provider.json')
    require(selected.get('schema') == 'pon-credit-selected-provider-v1'
            and selected.get('provider_directory') == str(PROVIDER2)
            and selected.get('receipt_path') == str(PROVIDER2 / 'observations/pq-provider/provider.json')
            and selected.get('receipt_sha256') == digest(provider['observations/pq-provider/provider.json'])
            and selected.get('receipt') == receipt and selected.get('private_smoke_key_read_or_copied') is False
            and selected.get('native_rust_pq_tests_claimed_by_this_proof') is False
            and selected.get('production_activation') is False, 'selected provider differs from public retained receipt')

    retained = {}
    for prefix, files in ((INITIAL_PREFIX, first), (CURRENT_PREFIX, current),
                          ('review-observations', review), ('provider-current', provider)):
        for name, data in files.items():
            retained[prefix + '/' + name] = data
    additions = {INITIAL_PREFIX + '/runtime-job-status.json': status_raw[0],
                 CURRENT_PREFIX + '/runtime-job-status.json': status_raw[1],
                 'provider-initial-cancelled/build-and-smoke.log': cancelled_log,
                 'provider-initial-cancelled/runtime-job-status.json': status_raw[2]}
    require(not set(additions) & set(retained), 'raw runtime output already contains a conflicting job status')
    retained.update(additions)
    for name, data in retained.items():
        public_bytes(name, data)
    readme_path = EVIDENCE / 'README.md'
    readme = checked_file(readme_path)
    require(readme == git_bytes('show', tested + ':' + EVIDENCE_REL + '/README.md')
            and MARKER.encode() not in readme, 'README changed or already contains this retention')
    new_readme = readme + readme_append(initial_summary, current_summary,
                                      document(current, 'source-before.json')).encode('utf-8')
    for directory in (INITIAL_PREFIX, CURRENT_PREFIX, 'review-observations',
                      'provider-current', 'provider-initial-cancelled'):
        require(not (EVIDENCE / directory).exists() and not (EVIDENCE / directory).is_symlink(),
                'retention destination already exists: ' + directory)
    require(not (EVIDENCE / 'receipt-index.json').exists() and not FINAL.exists()
            and FINAL.parent.resolve(strict=True) == FINAL.parent, 'retention index or final destination already exists')
    require(git('rev-parse', 'HEAD') == tested, 'HEAD moved during retention input review')
    clean()
    execute(['bash', 'scripts/project-preflight.sh'])
    require(git('rev-parse', 'HEAD') == tested, 'HEAD moved before retention writes')
    clean()

    # The first worktree writes occur only after every validation gate above.
    for name, data in sorted(retained.items()):
        target = EVIDENCE / name
        target.parent.mkdir(parents=True, exist_ok=True)
        require(target.parent.resolve(strict=True) == target.parent, 'symlink appeared in destination parents')
        with target.open('xb') as stream:
            stream.write(data)
    require(checked_file(readme_path) == readme, 'README changed before append')
    with readme_path.open('ab') as stream:
        stream.write(new_readme[len(readme):])
    manifest_files = {**retained, 'README.md': new_readme}
    manifest = [{'path': name, 'bytes': len(data), 'sha256': digest(data)}
                for name, data in sorted(manifest_files.items())]
    index = {
        'schema': 'pon-credit-envelope-retained-receipt-index-v2', 'created_utc': now(),
        'tested_source': tested, 'tested_tree': tree, 'initial_tested_source': INITIAL,
        'initial_tested_tree': initial_tree, 'review_packet_sha256': args.review_sha256,
        'current_stage_count': 17, 'current_all_stages_passed': True,
        'initial_failed_stages': ['inventory-check', 'rust-clippy'],
        'historical_controls_not_rerun': HISTORICAL_COUNTS,
        'provider_initial_result': 'CANCELLED', 'provider_current_result': 'PREPARED_AND_SMOKE_VERIFIED',
        'files': manifest, 'overall_security_qualification': 'HOLD', 'production_activation': False,
    }
    with (EVIDENCE / 'receipt-index.json').open('x', encoding='utf-8') as stream:
        json.dump(index, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    for row in manifest:
        data = checked_file(EVIDENCE / row['path'])
        require(len(data) == row['bytes'] and digest(data) == row['sha256'], 'retained bytes differ from manifest')
    expected_paths = {EVIDENCE_REL + '/' + name for name in manifest_files} | {EVIDENCE_REL + '/receipt-index.json'}
    require(names(git_bytes('diff', '--name-only', '-z')) == [EVIDENCE_REL + '/README.md']
            and not git_bytes('diff', '--cached', '--name-only', '-z'), 'unexpected tracked or staged changes')
    execute(['git', 'diff', '--check'])
    # *.log is ignored in this repository: force-add only this exact authorized list.
    execute(['git', 'add', '--force', '--', *sorted(expected_paths)])
    require(set(names(git_bytes('diff', '--cached', '--name-only', '-z'))) == expected_paths,
            'staged evidence does not contain every frozen raw file')
    require(non_evidence(git('write-tree')) == non_evidence(tested), 'staged non-evidence source changed')
    expected_blobs = {EVIDENCE_REL + '/' + name: data for name, data in manifest_files.items()}
    expected_blobs[EVIDENCE_REL + '/receipt-index.json'] = checked_file(EVIDENCE / 'receipt-index.json')
    for name, data in expected_blobs.items():
        require(git_bytes('show', ':' + name) == data, 'staged raw evidence bytes changed: ' + name)
    require(not git_bytes('diff', '--name-only', '-z')
            and not git_bytes('ls-files', '--others', '--exclude-standard', '-z'), 'unstaged or unrelated untracked changes')
    execute(['bash', 'scripts/project-preflight.sh', '--staged'])
    require(git('rev-parse', 'HEAD') == tested
            and set(names(git_bytes('diff', '--cached', '--name-only', '-z'))) == expected_paths
            and non_evidence(git('write-tree')) == non_evidence(tested), 'source or staged entries moved before commit')
    execute(['git', '-c', 'user.name=Qian QI', '-c', 'user.email=102159240+ProfHepta@users.noreply.github.com',
             'commit', '-m', 'test(pon): retain initial refusals and repaired credit-contract execution'])
    publication = git('rev-parse', 'HEAD')
    require(git('show', '-s', '--format=%P', publication) == tested
            and non_evidence(publication) == non_evidence(tested)
            and set(names(git_bytes('diff', '--name-only', '-z', tested, publication))) == expected_paths,
            'publication commit changed tested non-evidence source or unexpected evidence')
    for name, data in expected_blobs.items():
        require(git_bytes('show', publication + ':' + name) == data,
                'committed raw evidence bytes changed: ' + name)
    clean()
    FINAL.mkdir(exist_ok=False)
    final = {
        'schema': 'pon-credit-envelope-publication-source-v1', 'tested_source': tested,
        'tested_tree': tree, 'initial_tested_source': INITIAL,
        'publication_commit': publication, 'publication_tree': git('rev-parse', publication + '^{tree}'),
        'non_evidence_entries_identical': True, 'non_evidence_entries': len(non_evidence(publication)),
        'retained_receipt_files': len(manifest), 'retained_receipt_bytes': sum(row['bytes'] for row in manifest),
        'receipt_index_sha256': digest(checked_file(EVIDENCE / 'receipt-index.json')),
        'review_packet_sha256': args.review_sha256,
        'overall_security_qualification': 'HOLD', 'production_activation': False,
    }
    with (FINAL / 'publication-source.json').open('x', encoding='utf-8') as stream:
        json.dump(final, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps(final, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
