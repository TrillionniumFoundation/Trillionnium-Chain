#!/usr/bin/env python3
"""Task-local, bounded native gate for frozen A; preserves all old observations."""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import gzip
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
import types

ROOT = Path('/home/qian-qi/work/chain-qrom-local-20261107-7150')
PARENT = Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence')
OUT = PARENT / 'native-1e4bffc371bc'
OLD_OUT = PARENT / 'native-7150'
TARGET = OLD_OUT / 'cargo-target'
OLD = '7150d96a2112875b4afcf3023361a5cef4a0e4b1'
BASE = '1a14f7d4826363daefac9ec10131c66d7e70ece7'
BASE_TREE = 'e08b5dcd9ae2e90d0a36cb5d85e6ce1def387e85'
HEAD = '1e4bffc371bcdc53aabc621b6b6cb2485ab36f53'
TREE = '23c95cb4acfcfd2b1355d9d6e33c4c18b3f332a0'
BASE_BUNDLE = PARENT / 'W1_QROM_closure_1a14f7d48263.bundle'
A_BUNDLE = PARENT / 'W1_QROM_native_fixes_1e4bffc371bc.bundle'
BASE_SHA = '9aa10404c58ba6e053dec7e7724a92861c033e05518c896d82b00a4a3a2f8085'
A_SHA = '65835d8b22e2a506ace76a4adcae377499580ed72a0ad91ee7362f836a2a5084'
HELPERS = {
    'base_helper.py': ('run_native.py', 'bee8d87d76b98e9fbb3b33a60a11be1c8d7c4197d0e7ab1e37e8126f7c983fc4'),
    'dependency_helper.py': ('check_dependencies_v2.py', '301c39565411bb6eb87e5200420c2f18ab76740e9e6675983ecef9678b6463b3'),
}
V2 = 'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml'
INGRESS = 'ingress::public_v3::tests::write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work'
V2_NAMES = {
    'tests::expected_artifacts_are_exact_and_never_derived_from_receipt',
    'tests::saved_full_v2_receipt_verifies_with_independent_artifacts',
    'tests::historical_full_receipt_cannot_satisfy_v2_statement',
}
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', CARGO_BUILD_JOBS='2',
           CARGO_TARGET_DIR=str(TARGET), CARGO_TERM_COLOR='never')
RECORDS = []
IDENTITIES = []
NARROW_REQUIRED = []
CHECKS = {}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write(name, data):
    with (OUT / name).open('x') as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write('\n')


def read(name):
    return json.loads((OUT / name).read_text())


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=ROOT)


def frozen(expected=HEAD):
    actual = git('rev-parse', 'HEAD').decode().strip()
    if actual != expected:
        raise ValueError('source HEAD changed: ' + actual)
    if expected == HEAD and git('rev-parse', 'HEAD^{tree}').decode().strip() != TREE:
        raise ValueError('candidate tree mismatch')


def status_update():
    temp = OUT / 'stage-status.tmp'
    temp.write_text(json.dumps({'head': HEAD, 'records': RECORDS,
        'full_tracked_identity_claimed': False}, indent=2, sort_keys=True) + '\n')
    temp.replace(OUT / 'stage-status.json')


def observe(name, argv, timeout=600, expected=0, frozen_head=HEAD, required=False, environment=None):
    frozen(frozen_head)
    if required:
        NARROW_REQUIRED.append(name)
    start = datetime.now(timezone.utc).isoformat()
    begin = time.monotonic()
    stdout, stderr = OUT / (name + '.stdout.log'), OUT / (name + '.stderr.log')
    timed_out, launch_error, code, pid = False, None, None, None
    print(json.dumps({'stage_started': name, 'command': argv}), flush=True)
    with stdout.open('xb') as so, stderr.open('xb') as se:
        try:
            process = subprocess.Popen(argv, cwd=ROOT, env=ENV if environment is None else environment,
                stdout=so, stderr=se, start_new_session=True)
            pid = process.pid
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            code = process.returncode
        except OSError as error:
            launch_error = str(error)
            se.write((launch_error + '\n').encode())
    ok = not timed_out and launch_error is None and code == expected
    row = {'name': name, 'command': argv, 'cwd': str(ROOT),
        'source_commit_before_command': frozen_head,
        'source_commit_after_command': git('rev-parse', 'HEAD').decode().strip(),
        'started_utc': start, 'elapsed_seconds': time.monotonic() - begin,
        'timeout_seconds': timeout, 'timed_out': timed_out, 'process_group': pid,
        'exit_code': code, 'expected_exit': expected, 'expectation_met': ok,
        'launch_error': launch_error,
        'stdout_bytes': stdout.stat().st_size, 'stdout_sha256': sha(stdout),
        'stderr_bytes': stderr.stat().st_size, 'stderr_sha256': sha(stderr),
        'post_quantum_soundness_qualified': False, 'consensus_admission': False}
    write(name + '.json', row)
    RECORDS.append(row)
    status_update()
    print(json.dumps(row, sort_keys=True), flush=True)
    return ok


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def helper(name):
    data = (OUT / name).read_bytes()
    if digest(data) != HELPERS[name][1]:
        raise ValueError('pinned helper differs: ' + name)
    module = types.ModuleType('native_task_' + name.replace('.', '_'))
    module.__file__ = str(OUT / name)
    exec(compile(data, module.__file__, 'exec'), module.__dict__)
    return module


def worktree(name):
    raw = git('status', '--porcelain=v1', '-z', '--untracked-files=all')
    (OUT / (name + '.porcelain')).write_bytes(raw)
    rows, pieces, i = [], raw.split(b'\0'), 0
    while i < len(pieces):
        piece = pieces[i]
        i += 1
        if not piece:
            continue
        row = {'status': piece[:2].decode(), 'path': piece[3:].decode()}
        if 'R' in row['status'] or 'C' in row['status']:
            row['original_path'] = pieces[i].decode()
            i += 1
        rows.append(row)
    result = {'head': git('rev-parse', 'HEAD').decode().strip(), 'records': rows,
        'record_count': len(rows), 'porcelain_sha256': digest(raw),
        'full_tracked_clean': not rows, 'full_tracked_identity_claimed': False,
        'all_reported_changes_are_deleted_evidence': all(r['status'] == ' D' and
            r['path'].startswith('evidence/') for r in rows)}
    write(name + '.json', result)
    return result


def configuration(name):
    paths = [Path.home() / '.cargo/config', Path.home() / '.cargo/config.toml',
        ROOT / '.cargo/config', ROOT / '.cargo/config.toml',
        ROOT / 'trillionnium/.cargo/config', ROOT / 'trillionnium/.cargo/config.toml',
        ROOT / 'formal/pon-nakamoto-v1/w1_v2_verifier/.cargo/config',
        ROOT / 'formal/pon-nakamoto-v1/w1_v2_verifier/.cargo/config.toml']
    rows = []
    for path in paths:
        row = {'path': str(path), 'present': path.is_file()}
        if row['present']:
            row.update(bytes=path.stat().st_size, sha256=sha(path))
        rows.append(row)
    flags = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
        'RUSTC_WORKSPACE_WRAPPER', 'RUSTC', 'CARGO_HOME']
    result = {'files': rows, 'selected_environment_identity': {
        key: {'present': key in ENV, 'value_sha256': digest(ENV[key].encode()) if key in ENV else None}
        for key in flags}, 'contents_and_environment_values_disclosed': False,
        'hermetic_build_claimed': False}
    write(name + '.json', result)
    return result


def stable_bytes(relative):
    path = ROOT / relative
    # Refuse symlink traversal beneath the selected worktree root.
    for parent in path.parents:
        if parent == ROOT:
            break
        if not parent.is_relative_to(ROOT) or parent.is_symlink():
            raise ValueError('symlink or escaping selected parent')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('selected input is not a regular file')
    fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
            raise ValueError('selected input changed before read')
        data = stream.read()
        if fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
            raise ValueError('selected input changed during read')
    if fingerprint(path.lstat()) != fingerprint(before):
        raise ValueError('selected path changed after read')
    return data, '100755' if before.st_mode & 0o111 else '100644'


def source_snapshot(name, base):
    frozen()
    entries = base.tree()
    includes = base.include_inventory(entries)
    changed = [p.decode() for p in git('diff', '--name-only', '-z', OLD, HEAD).split(b'\0') if p]
    selected = {p for p in entries if not p.startswith('evidence/')}
    selected.update(base.FIXED)
    selected.update(p for p in changed if p in entries)
    selected.update(row['target'] for row in includes['resolved'])
    rows = []
    for relative in sorted(selected):
        expected = entries.get(relative)
        row = {'path': relative, 'expected': expected}
        try:
            data, mode = stable_bytes(relative)
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            row.update(bytes=len(data), sha256=digest(data), actual_git_blob=blob,
                actual_git_mode=mode, matches_head=expected is not None and
                blob == expected['git_blob'] and mode == expected['mode'])
        except (OSError, ValueError) as error:
            row.update(matches_head=False, error=str(error))
        rows.append(row)
    deleted_changed = [p for p in changed if p not in entries]
    result = {'schema': 'TRNM-W1-NATIVE-SELECTED-SOURCE2', 'head': HEAD, 'tree': TREE,
        'selected_count': len(rows), 'non_evidence_tracked_count': sum(not p.startswith('evidence/') for p in entries),
        'selected_bytes_and_modes_match_head': all(r['matches_head'] for r in rows),
        'all_baseline_changed_deleted_paths_absent': all(not (ROOT / p).exists() for p in deleted_changed),
        'changed_since_baseline': changed, 'baseline': OLD,
        'files': rows, 'include_inventory': includes,
        'scope': 'All non-evidence tracked files, all retained paths changed since 7150, fixed verification inputs, and lexically resolved selected Rust include paths.',
        'full_tracked_identity_claimed': False, 'hermetic_build_claimed': False}
    write(name + '.json', result)
    print(json.dumps({'selected_snapshot': name, 'count': len(rows),
        'matches': result['selected_bytes_and_modes_match_head'],
        'unresolved_include_count': len(includes['unresolved']),
        'mismatches': [r['path'] for r in rows if not r['matches_head']]}), flush=True)
    return result


def identity(path, role):
    row = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path),
        'role': role, 'head': HEAD}
    IDENTITIES.append(row)
    return row


def compiled_list(stage):
    text = (OUT / (stage + '.stdout.log')).read_text()
    names = re.findall(r'^([^\s]+): test$', text, re.M)
    totals = re.findall(r'^(\d+) tests?, (\d+) benchmarks?$', text, re.M)
    if len(totals) != 1 or int(totals[0][0]) != len(names) or int(totals[0][1]) != 0:
        raise ValueError('missing or noncanonical compiled test roster: ' + stage)
    if len(set(names)) != len(names):
        raise ValueError('duplicate compiled test name: ' + stage)
    return names


def test_outcome(stage, expected, ignored=()):
    text = (OUT / (stage + '.stdout.log')).read_text()
    outcomes = [{'name': m.group(1), 'outcome': m.group(2), 'reason': m.group(3)} for m in
        re.finditer(r'^test ([^\s]+) \.\.\. (ok|FAILED|ignored)(?:, ([^\n]*))?$', text, re.M)]
    blocks = [dict(zip(['result', 'passed', 'failed', 'ignored', 'measured', 'filtered_out'],
        [m.group(1)] + [int(m.group(i)) for i in range(2, 7)])) for m in
        re.finditer(r'^test result: ([^.]+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;[^\n]*$', text, re.M)]
    ok_names = [r['name'] for r in outcomes if r['outcome'] == 'ok']
    ignored_names = [r['name'] for r in outcomes if r['outcome'] == 'ignored']
    complete = (len(blocks) == 1 and Counter(ok_names) == Counter(expected) and
        Counter(ignored_names) == Counter(ignored) and len(outcomes) == len(expected) + len(ignored) and
        blocks[0]['result'] == 'ok' and blocks[0]['passed'] == len(expected) and
        blocks[0]['failed'] == 0 and blocks[0]['ignored'] == len(ignored) and blocks[0]['measured'] == 0)
    result = {'stage': stage, 'expected_executed': sorted(expected),
        'expected_ignored': sorted(ignored), 'outcomes': outcomes, 'result_blocks': blocks,
        'exact_named_completion': complete, 'ignored_counted_as_pass': False,
        'stdout_sha256': sha(OUT / (stage + '.stdout.log'))}
    write(stage + '-completion.json', result)
    CHECKS[stage + '_named_completion'] = complete
    return result


def registry_extras():
    packages = []
    for key, row in sorted(read('resolved-dependencies-after.json')['packages'].items()):
        if row['source'] is None:
            continue
        root = Path(row['manifest_path']).parent
        archive = root.parents[2] / 'cache' / root.parent.name / (root.name + '.crate')
        with tarfile.open(archive, 'r:gz') as source:
            names = {m.name[len(root.name) + 1:] for m in source if m.isfile() and m.name.startswith(root.name + '/')}
        extras = []
        for path in sorted(root.rglob('*')):
            if path.is_dir():
                continue
            relative = str(path.relative_to(root))
            if relative in names:
                continue
            item = {'path': relative, 'regular_file': stat.S_ISREG(path.lstat().st_mode)}
            if item['regular_file']:
                item.update(bytes=path.stat().st_size, sha256=sha(path))
            extras.append(item)
        packages.append({'package_id': key, 'extras': extras})
    result = {'packages': packages, 'extra_file_count': sum(len(r['extras']) for r in packages),
        'all_extras_are_cargo_cache_markers': all(e['path'] in ('.cargo-ok', '.cargo-checksum.json') and
            e['regular_file'] for r in packages for e in r['extras']),
        'scope': 'Post-run extra-file inventory; archived source bytes are checked separately before compilation and after.'}
    write('registry-extra-files-after.json', result)
    CHECKS['registry_extras_are_cache_markers'] = result['all_extras_are_cargo_cache_markers']


def prepare():
    frozen(OLD)
    OUT.mkdir(exist_ok=False)
    (OUT / 'run_candidate.py').write_bytes(Path(__file__).read_bytes())
    for destination, (source, expected) in HELPERS.items():
        data = (OLD_OUT / source).read_bytes()
        need(digest(data) == expected, 'old pinned helper mismatch')
        (OUT / destination).write_bytes(data)
    dependency_wrapper = """from pathlib import Path
import hashlib, sys, types
out=Path(__file__).resolve().parent
data=(out/'dependency_helper.py').read_bytes()
assert hashlib.sha256(data).hexdigest()=='301c39565411bb6eb87e5200420c2f18ab76740e9e6675983ecef9678b6463b3'
module=types.ModuleType('pinned_dependency_helper')
module.__file__=str(out/'dependency_helper.py')
exec(compile(data,module.__file__,'exec'),module.__dict__)
module.ROOT=Path('/home/qian-qi/work/chain-qrom-local-20261107-7150')
module.OUT=out
module.EXPECTED='1e4bffc371bcdc53aabc621b6b6cb2485ab36f53'
raise SystemExit(module.main())
"""
    (OUT / 'run_dependencies.py').write_text(dependency_wrapper)
    write('runner-identity.json', {'script_sha256': sha(OUT / 'run_candidate.py'),
        'pinned_helpers': HELPERS, 'candidate': HEAD, 'tree': TREE,
        'warm_target': str(TARGET), 'CARGO_BUILD_JOBS': '2',
        'source_edits_authorized': False, 'source_transition': 'Normal bundle fetch and fast-forward only.',
        'full_workspace_tests_rerun': False, 'prior_7150_failures_superseded': False})
    need(observe('bootstrap-preflight', ['bash', 'scripts/project-preflight.sh', '--audit'],
        frozen_head=OLD), 'preflight rejected bootstrap')
    worktree('source-worktree-before-fetch')
    need(BASE_BUNDLE.stat().st_size == 4778605 and sha(BASE_BUNDLE) == BASE_SHA, 'base bundle identity mismatch')
    write('base-bundle-identity.json', {'path': str(BASE_BUNDLE), 'bytes': BASE_BUNDLE.stat().st_size,
        'sha256': sha(BASE_BUNDLE), 'expected_commit': BASE})
    need(observe('base-bundle-verify', ['git', 'bundle', 'verify', str(BASE_BUNDLE)], frozen_head=OLD),
        'base bundle verification failed')
    need(observe('base-bundle-fetch', ['git', 'fetch', '--no-tags', str(BASE_BUNDLE), BASE], frozen_head=OLD),
        'base bundle fetch failed')
    need(git('rev-parse', BASE + '^{tree}').decode().strip() == BASE_TREE, 'base tree mismatch')
    write('prepare-complete.json', {'head_unchanged': OLD, 'base_fetched': BASE,
        'candidate_bundle_read_or_fetched': False, 'script_sha256': sha(OUT / 'run_candidate.py')})
    print(json.dumps({'prepared': True, 'out': str(OUT)}), flush=True)


def advance():
    frozen(OLD)
    need(read('prepare-complete.json')['base_fetched'] == BASE, 'bootstrap did not complete')
    need(A_BUNDLE.stat().st_size == 2348492 and sha(A_BUNDLE) == A_SHA, 'candidate bundle identity mismatch')
    write('candidate-bundle-identity.json', {'path': str(A_BUNDLE), 'bytes': A_BUNDLE.stat().st_size,
        'sha256': sha(A_BUNDLE), 'expected_commit': HEAD})
    need(observe('candidate-bundle-verify', ['git', 'bundle', 'verify', str(A_BUNDLE)], frozen_head=OLD),
        'candidate bundle verification failed')
    need(observe('candidate-bundle-fetch', ['git', 'fetch', '--no-tags', str(A_BUNDLE), HEAD], frozen_head=OLD),
        'candidate bundle fetch failed')
    need(observe('candidate-ancestry', ['git', 'merge-base', '--is-ancestor', OLD, HEAD], frozen_head=OLD),
        'candidate is not a descendant of old frozen source')
    need(observe('candidate-fast-forward', ['git', 'merge', '--ff-only', '--no-edit', HEAD], frozen_head=OLD),
        'normal fast-forward refused; do not force or reset')
    frozen()


def run_native():
    base = helper('base_helper.py')
    base.REPO, base.OUT, base.HEAD, base.TARGET, base.ENV = ROOT, OUT, HEAD, TARGET, ENV
    source_args = ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD]
    before = None
    statuses = None
    configs = None
    try:
        advance()
        need(observe('preflight-audit', ['bash', 'scripts/project-preflight.sh', '--audit'], required=True),
            'candidate preflight failed')
        observe('full-source-before', source_args + ['--output', str(OUT / 'full-source-before-result.json')])
        statuses = worktree('source-worktree-before')
        before = source_snapshot('selected-source-before', base)
        CHECKS['selected_before_matches'] = before['selected_bytes_and_modes_match_head']
        need(CHECKS['selected_before_matches'] and before['all_baseline_changed_deleted_paths_absent'],
            'selected compilation or fixture source differs from A; no compilation attempted')
        CHECKS['selected_literal_includes_resolved'] = not before['include_inventory']['unresolved']
        need(CHECKS['selected_literal_includes_resolved'], 'unresolved selected include requires review')
        configs = configuration('cargo-config-before')
        need(observe('cargo-metadata-chain', ['cargo', 'metadata', '--manifest-path',
            'trillionnium/Cargo.toml', '--locked', '--format-version', '1'], timeout=900, required=True),
            'locked chain metadata failed')
        need(observe('cargo-metadata-v2', ['cargo', 'metadata', '--manifest-path', V2,
            '--locked', '--format-version', '1'], timeout=900, required=True), 'locked v2 metadata failed')
        need(observe('dependencies-before', ['python3', str(OUT / 'run_dependencies.py'), 'before'],
            timeout=900, required=True), 'resolved dependency source verification failed before compilation')
        base.v2_feature_check()
        CHECKS['v2_features_checked'] = True
        write('dependency-audit-timing-note.json', {'phase': 'before any candidate test/build/Clippy command',
            'candidate': HEAD, 'warm_target_exists_from_prior_7150': True,
            'fresh_hermetic_rebuild_claimed': False, 'all_registry_archived_source_bytes_and_lock_checksums_checked': True})
        observe('cargo-fmt', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml',
            '--all', '--', '--check'], required=True)
        observe('rustc-version', ['rustc', '-Vv'], required=True)
        observe('cargo-version', ['cargo', '-Vv'], required=True)
        node = ['cargo', 'test', '--manifest-path', 'trillionnium/Cargo.toml', '--locked',
            '-p', 'trnm-pon-node', '--lib']
        listed = observe('release-owner-list', node + ['release_owner::', '--', '--list'],
            timeout=2700, required=True)
        ignored_listed = observe('release-owner-ignored-list', node + ['release_owner::', '--', '--ignored', '--list'],
            timeout=2700, required=True)
        if listed and ignored_listed:
            all_names = compiled_list('release-owner-list')
            ignored_names = compiled_list('release-owner-ignored-list')
            need(all(n.startswith('release_owner::') for n in all_names) and
                set(ignored_names).issubset(all_names) and all_names, 'invalid release owner roster')
            wanted = sorted(set(all_names) - set(ignored_names))
            write('release-owner-compiled-roster.json', {'head': HEAD, 'all_registered': all_names,
                'registered_ignored': ignored_names, 'expected_executed': wanted,
                'lib_only': True, 'nonignored_count': len(wanted), 'ignored_count': len(ignored_names),
                'ignored_tests_do_not_count_as_pass': True})
            stderr = (OUT / 'release-owner-list.stderr.log').read_text()
            executables = re.findall(r'Running unittests [^\n]* \(([^\n]+)\)', stderr)
            need(len(executables) == 1, 'ambiguous node test binary identity')
            identity(Path(executables[0]), 'compiled node lib test binary before module execution')
            observe('release-owner-tests', node + ['release_owner::', '--', '--test-threads=1'],
                timeout=2700, required=True)
            test_outcome('release-owner-tests', wanted, ignored_names)
        else:
            CHECKS['release-owner-tests_named_completion'] = False
        observe('ingress-exact-test', node + [INGRESS, '--', '--exact', '--nocapture', '--test-threads=1'],
            timeout=90, required=True)
        test_outcome('ingress-exact-test', {INGRESS})
        observe('v2-native-tests', ['cargo', 'test', '--manifest-path', V2, '--locked'],
            timeout=1800, required=True)
        test_outcome('v2-native-tests', V2_NAMES)
        built = observe('v2-release-build', ['cargo', 'build', '--release', '--manifest-path', V2, '--locked'],
            timeout=1800, required=True)
        if built:
            binary = TARGET / 'release/w1-verify-v2'
            identity(binary, 'fixed v2 release verifier before verification')
            receipt, header, artifacts = [str(ROOT / base.FIXTURE / n) for n in
                ['succinct.bin', 'header.bin', 'expected-artifacts.bin']]
            valid = [str(binary), receipt, header, artifacts]
            observed_receipt = observe('v2-fixed-receipt', valid, required=True)
            observed_native = observe('v2-complete-native', [str(binary), '--native',
                str(ROOT / base.FIXTURE / 'input.bin'), artifacts], timeout=600, required=True)
            if observed_receipt and observed_native:
                vr, vn = [json.loads((OUT / (n + '.stdout.log')).read_text()) for n in
                    ['v2-fixed-receipt', 'v2-complete-native']]
                result = {'receipt_schema': vr.get('schema'), 'native_schema': vn.get('schema'),
                    'matching_fields': {key: vr.get(key) == vn.get(key) and vr.get(key) is not None for key in
                        ['work_id', 'header_sha256', 'journal_sha256', 'expected_artifacts_sha256']},
                    'fixed_proof_trials': vr.get('independent_proof_trials'),
                    'one_input_full_native_replay_calls': vn.get('full_replay_calls'),
                    'one_input_timing_iterations': vn.get('iterations'),
                    'different_independent_native_inputs_claimed': False}
                result['pass'] = (vr.get('schema') == 'TRNM-W1-V2-FULL-VERIFY1' and
                    vn.get('schema') == 'TRNM-W1-V2-NATIVE1' and all(result['matching_fields'].values()) and
                    vr.get('independent_proof_trials') == 1 and vn.get('full_replay_calls') == 1001)
                write('v2-receipt-native-binding.json', result)
                CHECKS['v2_receipt_native_binding'] = result['pass']
            else:
                CHECKS['v2_receipt_native_binding'] = False
            bad_receipt = OUT / 'mutated-receipt.bin'
            data = bytearray(Path(receipt).read_bytes())
            data[76] ^= 1
            bad_receipt.write_bytes(data)
            bad_artifacts = OUT / 'mutated-artifacts.bin'
            data = bytearray(Path(artifacts).read_bytes())
            data[0] ^= 1
            bad_artifacts.write_bytes(data)
            for name, argv, marker in [
                ('v2-mutated-receipt', [str(binary), str(bad_receipt), header, artifacts], 'W1_V2_CRYPTO_REJECT'),
                ('v2-mutated-artifacts', [str(binary), receipt, header, str(bad_artifacts)], 'W1_V2_PUBLIC_REJECT'),
                ('v2-native-mutated-artifacts', [str(binary), '--native', str(ROOT / base.FIXTURE / 'input.bin'),
                    str(bad_artifacts)], 'PublicStatement')]:
                observe(name, argv, expected=1, required=True)
                CHECKS[name + '_rejection_reason'] = marker in (OUT / (name + '.stderr.log')).read_text()
            for key in ['RISC0_DEV_MODE', 'RISC0_PROVER', 'BONSAI_API_URL', 'BONSAI_API_KEY']:
                env = dict(ENV, **{key: 'task-negative-control-not-a-secret'})
                name = 'v2-environment-' + key.lower()
                observe(name, valid, expected=1, required=True, environment=env)
                CHECKS[name + '_rejection_reason'] = ('unexpected proof environment: ' + key) in (OUT / (name + '.stderr.log')).read_text()
        else:
            CHECKS['v2_release_verified'] = False
        observe('chain-strict-clippy', ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml',
            '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'], timeout=2700, required=True)
    except Exception as error:
        write('runner-error.json', {'type': type(error).__name__, 'error': str(error), 'candidate': HEAD})
        CHECKS['runner_completed_without_exception'] = False
        print(json.dumps({'runner_error': str(error)}), flush=True)
    finally:
        try:
            frozen()
            if (OUT / 'resolved-dependencies-before.json').exists():
                observe('dependencies-after', ['python3', str(OUT / 'run_dependencies.py'), 'after'],
                    timeout=900, required=True)
                if (OUT / 'resolved-dependencies-comparison.json').exists():
                    comparison = read('resolved-dependencies-comparison.json')
                    CHECKS['resolved_dependency_sources_unchanged'] = comparison['packages_and_source_files_unchanged'] and comparison['graphs_unchanged']
                    registry_extras()
            after = source_snapshot('selected-source-after', base)
            statuses_after = worktree('source-worktree-after')
            configs_after = configuration('cargo-config-after')
            CHECKS['selected_after_matches'] = after['selected_bytes_and_modes_match_head']
            CHECKS['selected_source_unchanged'] = before is not None and before['files'] == after['files']
            CHECKS['worktree_status_unchanged'] = statuses is not None and statuses['records'] == statuses_after['records']
            CHECKS['selected_config_unchanged'] = configs is not None and configs == configs_after
            write('selected-source-comparison.json', {'head': HEAD, 'tree': TREE,
                'before_sha256': sha(OUT / 'selected-source-before.json') if before else None,
                'after_sha256': sha(OUT / 'selected-source-after.json'),
                'selected_count': after['selected_count'], 'checks': dict(CHECKS),
                'full_tracked_identity_claimed': False})
            identity_rows = []
            for row in IDENTITIES:
                actual = sha(Path(row['path']))
                identity_rows.append(dict(row, after_sha256=actual, unchanged=actual == row['sha256']))
            write('binary-identities.json', {'head': HEAD, 'files': identity_rows,
                'all_unchanged': all(row['unchanged'] for row in identity_rows)})
            CHECKS['executed_binary_identities_unchanged'] = bool(identity_rows) and all(row['unchanged'] for row in identity_rows)
            observe('full-source-after', source_args + ['--output', str(OUT / 'full-source-after-result.json')])
        except Exception as error:
            write('after-error.json', {'type': type(error).__name__, 'error': str(error)})
            CHECKS['after_completed_without_exception'] = False
        summary_and_package()


def summary_and_package():
    frozen()
    names = [r['name'] for r in RECORDS]
    required_set = set(NARROW_REQUIRED)
    required_complete = (len(required_set) == len(NARROW_REQUIRED) and
        all(names.count(n) == 1 for n in NARROW_REQUIRED) and
        all(r['expectation_met'] for r in RECORDS if r['name'] in required_set))
    milestone = {'preflight-audit', 'cargo-metadata-chain', 'cargo-metadata-v2', 'dependencies-before',
        'cargo-fmt', 'release-owner-list', 'release-owner-ignored-list', 'release-owner-tests',
        'ingress-exact-test', 'v2-native-tests', 'v2-release-build', 'v2-fixed-receipt', 'v2-complete-native',
        'v2-mutated-receipt', 'v2-mutated-artifacts', 'v2-native-mutated-artifacts', 'chain-strict-clippy', 'dependencies-after'}
    checks_pass = bool(CHECKS) and all(CHECKS.values())
    narrow_pass = required_complete and milestone.issubset(required_set) and checks_pass
    summary = {'schema': 'TRNM-W1-NATIVE-CANDIDATE-OBSERVATIONS1', 'head': HEAD, 'tree': TREE,
        'warm_cache_origin_commit': OLD, 'target_dir': str(TARGET), 'CARGO_BUILD_JOBS': '2',
        'narrow_candidate_gate_pass': narrow_pass, 'all_observed_command_expectations_met': all(r['expectation_met'] for r in RECORDS),
        'required_narrow_stages': NARROW_REQUIRED, 'semantic_and_identity_checks': CHECKS,
        'commands': RECORDS, 'command_count': len(RECORDS),
        'failed_observations': [r['name'] for r in RECORDS if not r['expectation_met']],
        'full_tracked_identity_claimed': False, 'full_workspace_tests_executed': False,
        'original_7150_timeout_and_failures_preserved': True,
        'fixed_v2_release_feature_scope': 'Only this fixed release verifier, manifest/lock graph, binary, fixed receipt, native input, and recorded environment negatives.',
        'complete_program_or_production_supply_chain_qualified': False,
        'post_quantum_soundness_qualified': False, 'unconditional_project_security_bits': None,
        'consensus_admission': False, 'release_authorized': False,
        'source_after': read('selected-source-comparison.json') if (OUT / 'selected-source-comparison.json').exists() else None,
        'release_owner_completion': read('release-owner-tests-completion.json') if (OUT / 'release-owner-tests-completion.json').exists() else None,
        'ingress_completion': read('ingress-exact-test-completion.json') if (OUT / 'ingress-exact-test-completion.json').exists() else None,
        'v2_completion': read('v2-native-tests-completion.json') if (OUT / 'v2-native-tests-completion.json').exists() else None}
    write('native-summary.json', summary)
    files = [p for p in sorted(OUT.iterdir()) if p.is_file() and p.name not in ('observations.tar.gz', 'manifest.json', 'package-result.json')]
    payload = [{'path': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in files]
    manifest = {'schema': 'TRNM-W1-NATIVE-CANDIDATE-ARCHIVE1', 'head': HEAD, 'tree': TREE,
        'payload_files': payload, 'payload_count': len(payload),
        'large_targets_and_executables_included': False, 'credentials_or_environment_values_included': False,
        'full_tracked_identity_claimed': False, 'post_quantum_soundness_qualified': False}
    write('manifest.json', manifest)
    with (OUT / 'observations.tar.gz').open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
            with tarfile.open(mode='w', fileobj=zipped) as archive:
                for path in files + [OUT / 'manifest.json']:
                    data = path.read_bytes()
                    info = tarfile.TarInfo(path.name)
                    info.size, info.mode, info.mtime = len(data), 0o600, 0
                    archive.addfile(info, io.BytesIO(data))
    result = {'path': str(OUT / 'observations.tar.gz'), 'bytes': (OUT / 'observations.tar.gz').stat().st_size,
        'sha256': sha(OUT / 'observations.tar.gz'), 'payload_count': len(payload),
        'summary_sha256': sha(OUT / 'native-summary.json'), 'manifest_sha256': sha(OUT / 'manifest.json'),
        'narrow_candidate_gate_pass': narrow_pass, 'all_observed_command_expectations_met': summary['all_observed_command_expectations_met']}
    write('package-result.json', result)
    print(json.dumps({'native_gate_complete': result}, sort_keys=True), flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare-base']:
        prepare()
    elif sys.argv[1:] == ['--run']:
        RECORDS.extend(read('stage-status.json')['records'])
        run_native()
        raise SystemExit(0 if read('native-summary.json')['all_observed_command_expectations_met'] else 2)
    else:
        raise SystemExit('use --prepare-base or --run')
