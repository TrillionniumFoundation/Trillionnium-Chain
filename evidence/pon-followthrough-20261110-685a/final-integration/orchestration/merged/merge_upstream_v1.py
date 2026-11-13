#!/usr/bin/env python3
"""Create one reviewed ordinary merge and verify its source binding; no tests or push."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time

ROOT = Path('/home/qian-qi/chain-pon-followthrough-20261110-685a')
INPUTS = Path(str(ROOT) + '-inputs')
OUT = INPUTS / 'upstream-merge-01'
BUNDLE = INPUTS / 'upstream-merge-inputs-01'
ARCHIVE = INPUTS / 'upstream-merge-inputs-01.tar.gz'
ARCHIVE_SHA = 'da285a18285c8f4a14204c75e3a8b1795a2dcd3bdc3635af127b1e9bfe9ccbf0'
MANIFEST_SHA = 'b9b8f43a3df20dbb88257594e4efe40a7edfb3bf2d316259535aaff571e296d3'
BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
C3 = 'a715b2c8e89732ce356ebae67f978ef232156c04'
C3_TREE = 'cc44e4c526d9b52d04697169a9b1d3eeb5079451'
UPSTREAM = 'df927b6ffaecff293b9e9428e3ba516f47cd101a'
UPSTREAM_TREE = 'a883a05b590fb8b0113b3715f4294eee7a00275b'
BRANCH = 'fix/chain-pon-followthrough-20261110-685a'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
SOURCE_CHECK = 'scripts/ci/verify_ci_source.py'
REFRESH = 'scripts/refresh_distributed_source_inventory.py'
ENV = dict(os.environ, PATH='/home/qian-qi/.cargo/bin:' + os.environ.get('PATH', ''),
           PYTHONDONTWRITEBYTECODE='1', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
ROWS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def emit(name, value):
    path = OUT / name
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    tmp.replace(path)


def run(label, argv, *, allowed=(0,), timeout=600):
    emit('status.json', {'stage': label, 'phase': 'running', 'security_status': 'HOLD'})
    start = time.time_ns()
    error = None
    try:
        result = subprocess.run(argv, cwd=ROOT, env=ENV, capture_output=True, timeout=timeout, check=False)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as failure:
        code, stdout = 124, failure.stdout or b''
        stderr = (failure.stderr or b'') + b'\nmerge orchestration timeout\n'
        error = repr(failure)
    row = {'label': label, 'argv': argv, 'cwd': str(ROOT), 'exit_code': code,
           'launch_error': error, 'start_unix_ns': start, 'end_unix_ns': time.time_ns()}
    for stream_name, raw in [('stdout', stdout), ('stderr', stderr)]:
        path = OUT / (label + '.' + stream_name + '.log')
        with path.open('xb') as stream:
            stream.write(raw)
        row[stream_name] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
    ROWS.append(row)
    emit('commands.json', ROWS)
    if code not in allowed:
        raise RuntimeError(label + ' actual exit ' + str(code))
    return stdout


def git(*args):
    result = subprocess.run(['git', '--no-replace-objects', *args], cwd=ROOT, env=ENV,
                            capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError('Git read failed ' + repr(args) + ': ' + result.stderr.decode(errors='replace'))
    return result.stdout


def gtext(*args):
    return git(*args).decode().strip()


def require_clean_parent():
    assert gtext('rev-parse', 'HEAD') == C3
    assert gtext('rev-parse', 'HEAD^{tree}') == C3_TREE
    assert gtext('branch', '--show-current') == BRANCH
    assert git('status', '--porcelain') == b''
    assert all(not row or row.startswith(b'H ') for row in git('ls-files', '-v', '-z').split(b'\0'))
    assert not (Path(gtext('rev-parse', '--git-path', 'MERGE_HEAD'))).exists()


def replace_source(path, raw):
    target = ROOT / path
    assert target.is_file() and not target.is_symlink()
    metadata = target.stat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    target.write_bytes(raw)
    assert target.read_bytes() == raw and stat.S_IMODE(target.stat().st_mode) == stat.S_IMODE(metadata.st_mode)


assert not OUT.exists() and not BUNDLE.exists()
OUT.mkdir()
try:
    packed = ARCHIVE.read_bytes()
    assert len(packed) == 165643 and sha(packed) == ARCHIVE_SHA
    with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as archive:
        members = archive.getmembers()
        assert len(members) == 30 and len({entry.name for entry in members}) == 30
        assert all(entry.isfile() and not entry.name.startswith('/')
                   and all(part not in ('', '.', '..') for part in entry.name.split('/')) for entry in members)
        assert sum(entry.size for entry in members) == 675426
        payload = {entry.name: archive.extractfile(entry).read() for entry in members}
    assert sha(payload['manifest.json']) == MANIFEST_SHA
    manifest = json.loads(payload['manifest.json'])
    assert manifest['frozen'] is True and manifest['first_parent'] == C3 and manifest['second_parent'] == UPSTREAM
    assert set(payload) == {entry['path'] for entry in manifest['files']} | {'manifest.json'}
    for entry in manifest['files']:
        raw = payload[entry['path']]
        assert len(raw) == entry['bytes'] and sha(raw) == entry['sha256']
    BUNDLE.mkdir()
    for name, raw in payload.items():
        path = BUNDLE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    emit('inputs.json', {'archive_sha256': ARCHIVE_SHA, 'manifest_sha256': MANIFEST_SHA,
                         'members': len(payload), 'recorder_sha256': sha(Path(__file__).read_bytes())})
    require_clean_parent()
    run('project-preflight', ['bash', 'scripts/project-preflight.sh'])
    run('source-before', ['python3', '-B', SOURCE_CHECK, '--kind', 'head', '--expected-head', C3,
                          '--output', str(OUT / 'source-before.json')])
    assert run('github-account', ['gh', 'api', 'user', '--jq', '.login']).decode().strip() == 'ProfHepta'
    origin = gtext('remote', 'get-url', '--push', 'origin')
    repository = 'TrillionniumFoundation/Trillionnium-Chain'
    assert origin in ('https://github.com/' + repository + '.git', 'https://github.com/' + repository,
                      'git@github.com:' + repository + '.git')
    run('fetch-selected-upstream', ['git', 'fetch', '--no-tags', '--no-write-fetch-head',
                                    '--no-recurse-submodules', origin, UPSTREAM], timeout=900)
    require_clean_parent()
    assert gtext('rev-parse', UPSTREAM + '^{tree}') == UPSTREAM_TREE
    assert gtext('merge-base', C3, UPSTREAM) == BASE
    upstream_changes = {p.decode() for p in git('diff', '--name-only', '-z', BASE, UPSTREAM).split(b'\0') if p}
    upstream_sources = sorted(p for p in upstream_changes if not p.startswith(('evidence/', 'qualification/')))
    assert len(upstream_sources) == 13
    assert len(upstream_changes) == 209
    ci_manifest = json.loads(payload['ci-union/manifest.json'])
    repairs = json.loads(payload['inline-repair/repair-manifest.json'])
    for entry in ci_manifest['files']:
        before = git('show', C3 + ':' + entry['path'])
        after = payload['ci-union/candidate/' + entry['path']]
        assert len(before) == entry['before']['bytes'] and blob(before) == entry['before']['git_blob']
        assert sha(before) == entry['before']['sha256']
        assert len(after) == entry['after']['bytes'] and blob(after) == entry['after']['git_blob']
        assert sha(after) == entry['after']['sha256']
    repair_before = git('show', C3 + ':' + repairs['path'])
    repair_after = payload['inline-repair/candidate/' + repairs['path']]
    assert blob(repair_before) == repairs['before']['git_blob'] and sha(repair_before) == repairs['before']['sha256']
    assert blob(repair_after) == repairs['after']['git_blob'] and sha(repair_after) == repairs['after']['sha256']
    run('ordinary-merge-no-commit', ['git', 'merge', '--no-commit', '--no-ff', UPSTREAM], allowed=(0, 1))
    assert gtext('rev-parse', 'HEAD') == C3 and gtext('rev-parse', 'MERGE_HEAD') == UPSTREAM
    conflicts = {p.decode() for p in git('diff', '--name-only', '--diff-filter=U', '-z').split(b'\0') if p}
    allowed_conflicts = {PLAN, CORPUS, INVENTORY, '.github/workflows/pon-w1-work-security.yml',
                         'scripts/ci/test_w1_factorial_native_gate.py'}
    assert conflicts <= allowed_conflicts, conflicts
    emit('merge-observation.json', {'first_parent': C3, 'second_parent': UPSTREAM,
                                    'source_before_tree': C3_TREE, 'second_parent_tree': UPSTREAM_TREE,
                                    'actual_conflict_paths': sorted(conflicts),
                                    'upstream_non_evidence_paths': upstream_sources,
                                    'upstream_added_evidence_count': 196, 'merge_tests_executed': False})
    resolved = []
    for entry in ci_manifest['files']:
        replace_source(entry['path'], payload['ci-union/candidate/' + entry['path']])
        resolved.append(entry['path'])
    replace_source(repairs['path'], repair_after)
    resolved.append(repairs['path'])
    base_plan = git('show', BASE + ':' + PLAN)
    ours_plan = git('show', C3 + ':' + PLAN)
    theirs_plan = git('show', UPSTREAM + ':' + PLAN)
    assert ours_plan.startswith(base_plan) and theirs_plan.startswith(base_plan)
    assert len(ours_plan) > len(base_plan) and len(theirs_plan) > len(base_plan)
    merged_plan = base_plan + theirs_plan[len(base_plan):] + ours_plan[len(base_plan):]
    replace_source(PLAN, merged_plan)
    replace_source(CORPUS, git('show', C3 + ':' + CORPUS))
    replace_source(INVENTORY, git('show', C3 + ':' + INVENTORY))
    assert (ROOT / REFRESH).read_bytes() == git('show', BASE + ':' + REFRESH)
    run('regenerate-merged-source-inventory', ['python3', '-B', REFRESH])
    resolved += [PLAN, CORPUS, INVENTORY]
    run('stage-reviewed-resolutions', ['git', 'add', '--', *resolved])
    assert git('ls-files', '--unmerged', '-z') == b'' and git('diff', '--name-only', '-z') == b''
    assert git('ls-files', '--others', '--exclude-standard', '-z') == b''
    prepared_tree = gtext('write-tree')
    helper = BUNDLE / 'corpus/prepare_union_corpus.py'
    assert sha(helper.read_bytes()) == 'e25bc61e01248ebedcfc0bfddcdbab520fca4696391916de0a7b0c19fc54289e'
    corpus_out = OUT / 'corpus-preparation'
    run('prepare-live-union-corpus', ['python3', '-B', str(helper), 'prepare', '--root', str(ROOT),
                                    '--binding-child', C3, '--ours', C3, '--theirs', UPSTREAM,
                                    '--candidate-tree', prepared_tree, '--output', str(corpus_out)])
    patch = corpus_out / 'corpus-update.patch'
    run('check-corpus-patch', ['git', 'apply', '--check', str(patch)])
    run('apply-corpus-patch', ['git', 'apply', str(patch)])
    run('stage-corpus', ['git', 'add', '--', CORPUS])
    final_tree = gtext('write-tree')
    changed_paths = [p.decode() for p in git('diff', '--cached', '--name-only', '-z', C3).split(b'\0') if p]
    source_paths = sorted(p for p in changed_paths if not p.startswith(('evidence/', 'qualification/')))
    run('source-diff-whitespace', ['git', 'diff', '--cached', '--check', C3, '--', *source_paths])
    run('commit-preflight', ['bash', 'scripts/project-preflight.sh'])
    assert gtext('rev-parse', 'HEAD') == C3 and gtext('rev-parse', 'MERGE_HEAD') == UPSTREAM
    assert git('diff', '--name-only', '-z') == b'' and gtext('write-tree') == final_tree
    run('commit-reviewed-merge', ['git', 'commit', '-m',
                                 'merge(pon): retain parallel quorum work and complete source bindings'])
    merged = gtext('rev-parse', 'HEAD')
    assert gtext('rev-list', '--parents', '-n', '1', merged).split() == [merged, C3, UPSTREAM]
    assert gtext('rev-parse', merged + '^{tree}') == final_tree and git('status', '--porcelain') == b''
    receipt_sha = sha((corpus_out / 'receipt.json').read_bytes())
    run('verify-committed-union-corpus', ['python3', '-B', str(helper), 'verify', '--root', str(ROOT),
                                        '--prepared', str(corpus_out), '--receipt-sha256', receipt_sha,
                                        '--merge', merged, '--output', str(OUT / 'corpus-verification')])
    run('merged-source-identity', ['python3', '-B', SOURCE_CHECK, '--kind', 'head', '--expected-head', merged,
                                   '--output', str(OUT / 'source-merged.json')])
    result = {'schema': 'pon-reviewed-upstream-merge-v1', 'source_integration_complete': True,
              'source_binding_verified': True, 'first_parent': C3, 'second_parent': UPSTREAM,
              'merged_source': merged, 'merged_tree': final_tree, 'prepared_tree': prepared_tree,
              'corpus_preparation_receipt_sha256': receipt_sha, 'source_changed_paths': source_paths,
              'historical_c3_checks_passed': False, 'historical_c2_full_node_suite_passed': False,
              'merged_native_tests_executed': False, 'merged_required_checks_complete': False,
              'published': False, 'open_consensus_qualified': False, 'production_activation': False,
              'security_status': 'HOLD', 'recorder_sha256': sha(Path(__file__).read_bytes())}
    emit('summary.json', result)
    emit('status.json', {'stage': 'source-integration-complete', 'phase': 'finished', 'exit_code': 0,
                          'source': merged, 'security_status': 'HOLD'})
    print(json.dumps(result), flush=True)
except BaseException as error:
    emit('failure.json', {'source_integration_complete': False, 'reason': repr(error),
                          'no_automatic_rollback': True, 'published': False, 'security_status': 'HOLD'})
    emit('status.json', {'stage': 'failure', 'phase': 'failed', 'exit_code': 1, 'security_status': 'HOLD'})
    raise
