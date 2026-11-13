#!/usr/bin/env python3
"""Review-only until every native identity is pinned; publish one socket follow-up as Draft HOLD.

This wrapper reuses audited filesystem/Git helpers, never the earlier publisher's
main, validation plan, supplementary test, seal, or PR-body implementation.
"""
import argparse
import codecs
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import types

ROOT = Path('/data/chain-checkpoint-probe-20261112-df05')
CONTROL = Path('/data/chain-checkpoint-probe-source-20261112-df05')
OUT = Path('/data/chain-checkpoint-probe-validation-20261112-df05-v2')
STATE = Path('/data/chain-checkpoint-probe-publication-20261112-df05-v2')
PREFIX = 'evidence/checkpoint-socket-probe-20261112-df05'
BRANCH = 'fix/chain-checkpoint-probe-20261112-df05'
BASE_BRANCH = 'fix/chain-root-operation-owned-20261112-df05-v4'
BASE = '09e4801308366fac01e55bcbdcf8bdfd4e6d2810'
BASE_TREE = 'f322d45faaa204b641ed2565feca662ef096b161'
BASE_PR = 945
OLD_SOURCE = '87943f6229d8785c3f431ede5eadba62b634ab8c'
OLD_TREE = '5d2538f404e32319ea1084a6c79f37c52503546f'
OLD_PREFIX = 'evidence/root-execution-v6-20261112-df05-v3'
PREP_KEY = 'chain-checkpoint-probe-source-prep-20261112-df05-v1'
RUN_KEY = 'chain-checkpoint-probe-native-validation-20261112-df05-v2'
PUB_KEY = 'chain-checkpoint-probe-native-publication-20261112-df05-v2'
REPO = 'TrillionniumFoundation/Trillionnium-Chain'
ORIGIN = 'https://github.com/' + REPO + '.git'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
HELPER = Path('/data/chain-root-publication-bootstrap-20261112-df05-v2/root-native-publisher-v2-df05.py')
HELPER_SHA = '6b42ffccdd9ff216d1ec786813ba3059e0c89550ffbc8c6af6304f415884c40c'
HELPER_BYTES = 89391
VERIFIER_SHA = '0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946'
OWNER_SHA = '389154c792fd3c734621278fb4188e9863ff599efb0c9b863316f540a94eab4a'
SOURCE = '7d4303f1a9ba3c259b92e58b85126eef3c5378a1'
TREE = '2a580a0444f56c0e70e0d73a7fad1120367d1e9e'
DRIVER_SHA = '45af75877c19be74c3f0ae31214180c3765d4825f4ebf44af56de3711a01c210'
DRIVER_INPUT_SHA = '8e971550d9e38459169f28d81cc40072f8572cd81d1733b674ebc8e1f3a68fe6'
SOURCE_PREP_SHA = '07e8a8ecf0c3759608634ea62c85405b25b2019af705a9fb1f453ac89d673104'
PREPARATION = {
    'frozen_bytes': 3752,
    'frozen_sha256': '58038e56cfcaea54326b24e2135096994e4b79b3cb6ce84b1db1ba11577903c1',
    'input_sha256': '6579384ea2a04432b4cfa563b02fdc2afae38b71e416c454801d5b8380bdb6ba',
    'safe_manifest_sha256': '4e60535f7a6f5c2108052004a69d4fb3295b973352f3b3f08314dfb262563f28',
}
PARENT_PUBLICATION_RECEIPT = {'bytes': 576, 'sha256': '300d5e0a437cf83f9cbc1ae92793cd0b1e2e3b1e2f41f0974bf446d14bc11917'}
STAGED_IDENTITY = {'bytes': 764, 'sha256': '2912fa242b8cdcdbb1c2244da2e47d8749074f3e95e9d76e5722e241599cb166'}
CAP = 4 * 1024 * 1024
TARGET = Path('/data/chain-checkpoint-probe-target-20261112-df05-v2')
PRIOR_VALIDATION_OUT = Path('/data/chain-checkpoint-probe-validation-20261112-df05')
PRIOR_PUBLICATION_STATE = Path('/data/chain-checkpoint-probe-publication-20261112-df05')
PRIOR_VALIDATION_FAILURE = {'bytes': 955, 'sha256': 'e9095da2df962a6b8b5bf68e2ab3b93e1e7c03ae6884a652abcc07a566db12b0'}
# Expected canonical bytes from the original fixed driver/input. They are not
# claimed as an observed original until safe_history reads the native file.
PRIOR_VALIDATION_INVOCATION = {'bytes': 587, 'sha256': '73f55f8e8e7f10075e4ab561e873cbdafbb0b304ccb947aa08205d6cc9c5a005'}
PRIOR_TARGET = '/data/chain-root-operation-v6-df05-target-v3'
TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
PROVIDER = Path('/home/qian-qi/credit-envelope-f7e62-provider2/runner/trnm-pq-provider-3.5.9.5yXdk2mN/install')
PROVIDER_HASHES = {
    'bin/openssl': '41d5b79f937beed7f94d9623be504db72c5048fcd952965fc0e13305d2802a33',
    'include/openssl/opensslv.h': '9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda',
    'include/openssl/configuration.h': '406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996',
    'lib/libcrypto.a': '005a0f7d9f6a073e6530cc556c90b3c415df7c6bc2475e333d29aa9bfa409bfb',
    'lib/libssl.a': 'f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727',
}
POST_SHA = {
    'trillionnium/crates/trnm-checkpoint-store/src/lib.rs': '8ad6d9b14300c2df5d674604e4a0107e242c40d6a1e0f1a56d83763015b6f880',
    'trillionnium/crates/trnm-checkpoint-store/tests/socket_ownership.rs': '6c0482cab4ce234e32ebd388a856f1754aeaa48f299b1996f721420b0bac088f',
}
PLAN_ENTRY_SHA = '0458acbd35eed7528b2334643b0c19ed01bd960384d53321220809c16875e179'
SOCKET_NAMES = (
    'rejected_nonprivate_socket_parent_does_not_unlink_existing_listener',
    'different_admitted_journal_cannot_replace_a_live_checkpoint_endpoint',
    'copied_lease_record_cannot_replace_a_live_checkpoint_endpoint',
    'complete_checkpoint_request_rejects_a_copied_lease_replacement',
)
BASE_ARTIFACTS = {
    'driver.py', 'invocation.json', 'source-preparation.json', 'physical-before.json',
    'source-before.json', 'environment.json', 'plan.json', 'commands.json',
    'physical-after.json', 'source-after.json', 'SUMMARY.json',
    'prior-owner-closure.json', 'prior-publication-receipt.json', 'prior-environment.json',
    'prior-validation-finished.json', 'prior-socket-finished.json',
}
SAFE_PREP = {'driver.py', 'FOUR_PATH_DELTA.json', 'BASE_PHYSICAL.json', 'COMMITTED_PHYSICAL.json',
             'VERIFIED_PHYSICAL_SOURCE.json', 'STORAGE_ADMISSION.json', 'SHARED_CONFIG_IDENTITY.json'}
SAFE_PREP |= {'PREFLIGHT_' + label + suffix for label in ('BEFORE_EDIT', 'STAGED', 'COMMITTED')
              for suffix in ('.receipt.json', '.stdout', '.stderr')}
INDEX = ('-c', 'core.sparseCheckout=false', '-c', 'core.sparseCheckoutCone=false',
         '-c', 'core.ignorestat=false')
p = None


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def bootstrap_read(path):
    """Read the pinned helper through no-follow parent/file descriptors exactly once."""
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= CAP,
             'unsafe helper original')
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        fingerprint = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        with os.fdopen(descriptor, 'rb') as stream:
            need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), 'helper admission race')
            raw = stream.read(CAP + 1)
            need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), 'helper changed while reading')
        need(fingerprint(os.stat(path.name, dir_fd=directory, follow_symlinks=False)) == fingerprint(before)
             and len(raw) == before.st_size, 'helper pathname changed')
        return raw
    finally:
        os.close(directory)


def import_helpers():
    global p
    raw = bootstrap_read(HELPER)
    need(len(raw) == HELPER_BYTES and sha(raw) == HELPER_SHA, 'unreviewed helper bytes')
    p = types.ModuleType('checkpoint_probe_publisher_helpers')
    p.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), p.__dict__)
    for key, value in {'ROOT': ROOT, 'OUT': OUT, 'STATE': STATE, 'PREFIX': PREFIX,
                       'BRANCH': BRANCH, 'BASE_BRANCH': BASE_BRANCH, 'BASE': BASE,
                       'SOURCE': SOURCE, 'TREE': TREE, 'PUB_KEY': PUB_KEY}.items():
        setattr(p, key, value)
    return raw


def fully_bound():
    for name, value, length in (
        ('source', SOURCE, 40), ('tree', TREE, 40), ('driver', DRIVER_SHA, 64),
        ('driver input', DRIVER_INPUT_SHA, 64), ('source preparation', SOURCE_PREP_SHA, 64),
    ):
        need(re.fullmatch('[0-9a-f]{' + str(length) + '}', value), name + ' is UNBOUND')
    for item in (PARENT_PUBLICATION_RECEIPT, STAGED_IDENTITY, PRIOR_VALIDATION_FAILURE, PRIOR_VALIDATION_INVOCATION):
        need(set(item) == {'bytes', 'sha256'} and type(item['bytes']) is int and item['bytes'] > 0
             and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'prior safe receipt remains UNBOUND')


def write(path, raw):
    p.create_exact(path, raw)
    # Seal every newly-created directory entry as well as the file and leaf directory.
    for parent in (path.parent, *path.parent.parents):
        p.fsync_directory(parent)


def write_json(path, value):
    write(path, p.canonical(value))


def no_hold():
    for directory in (ROOT, CONTROL, OUT, STATE, PRIOR_VALIDATION_OUT, PRIOR_PUBLICATION_STATE):
        need(not os.path.lexists(directory / 'PUBLICATION_HOLD'), 'explicit publication HOLD marker')
    need(not os.path.lexists(CONTROL / 'FAILED.json'), 'source preparation failed')
    need(not os.path.lexists(OUT / 'FAILED.json'), 'native validation failed integrity/admission')


def planned_commands():
    cargo = str(TOOLCHAIN / 'cargo')
    metadata = [cargo, 'metadata', '--locked', '--offline', '--format-version', '1']
    py = ['/usr/bin/python3', '-B']
    return [
        ('preflight', ['bash', 'scripts/project-preflight.sh'], 120),
        ('rustc-version', [str(TOOLCHAIN / 'rustc'), '-Vv'], 120),
        ('cargo-version', [cargo, '-V'], 120),
        ('openssl-version', [str(PROVIDER / 'bin/openssl'), 'version', '-a'], 120),
        ('metadata-default', metadata + ['--manifest-path', 'trillionnium/Cargo.toml'], 300),
        ('metadata-all-features', metadata + ['--all-features', '--manifest-path', 'trillionnium/Cargo.toml'], 300),
        ('metadata-fuzz', metadata + ['--manifest-path', 'tests/fuzz/Cargo.toml'], 300),
        ('format', [cargo, 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'], 300),
        ('source-integrity-controls', py + ['-m', 'unittest', 'discover', '-s', 'scripts/ci', '-p', 'test_ci_source_integrity.py', '-v'], 600),
        ('repository-links', py + ['scripts/ci/check_repository.py'], 600),
        ('research-corpus', py + ['scripts/ci/check_pq_research_integration.py'], 600),
        ('source-inventory', py + ['scripts/refresh_distributed_source_inventory.py', '--check'], 300),
        ('checkpoint-package', [cargo, 'test', '--locked', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-checkpoint-store', '--', '--show-output', '--test-threads=1'], 1200),
        ('strict-workspace-clippy', [cargo, 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 3600),
    ]


def selected_environment():
    return {
        'PATH': str(TOOLCHAIN) + ':/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
        'CARGO_HOME': '/home/qian-qi/.cargo', 'CARGO_TARGET_DIR': str(TARGET),
        'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never', 'CARGO_NET_OFFLINE': 'true',
        'RUSTUP_TOOLCHAIN': '1.95.0', 'RUSTC': str(TOOLCHAIN / 'rustc'), 'RUSTDOC': str(TOOLCHAIN / 'rustdoc'),
        'OPENSSL_DIR': str(PROVIDER), 'OPENSSL_STATIC': '1', 'OPENSSL_NO_VENDOR': '1',
        'OPENSSL_LIB_DIR': str(PROVIDER / 'lib'), 'OPENSSL_INCLUDE_DIR': str(PROVIDER / 'include'),
        'TRNM_PQ_OPENSSL': str(PROVIDER / 'bin/openssl'), 'TRNM_PQ_OPENSSL_SHA256': PROVIDER_HASHES['bin/openssl'],
        'TRNM_PQ_OPENSSL_VERSION': '3.5.9', 'OPENSSL_CONF': '/dev/null',
        'OPENSSL_MODULES': str(PROVIDER / 'lib/ossl-modules'), 'TMPDIR': str(OUT / 'tmp'),
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPYCACHEPREFIX': str(OUT / 'pycache'), 'GIT_TERMINAL_PROMPT': '0',
    }


def checked_source_delta():
    need(p.gtext('rev-parse', SOURCE + '^{tree}') == TREE
         and p.gtext('show', '-s', '--format=%P', SOURCE) == BASE
         and p.gtext('rev-parse', BASE + '^{tree}') == BASE_TREE
         and p.gtext('show', '-s', '--format=%P', BASE) == OLD_SOURCE
         and p.gtext('rev-parse', OLD_SOURCE + '^{tree}') == OLD_TREE, 'source ancestry/tree differs')
    before, after = p.entries(BASE), p.entries(SOURCE)
    need(set(before) == set(after), 'source adds/deletes unreviewed paths')
    changed = {name for name in before if before[name] != after[name]}
    need(changed == {*POST_SHA, PLAN, CORPUS}, 'source delta is not four reviewed paths')
    for name in changed:
        need(before[name][0] == after[name][0] == '100644', 'source mode differs')
    for name, expected in POST_SHA.items():
        need(sha(p.git_blob(SOURCE, name)) == expected, 'source candidate bytes differ')
    old_plan, new_plan = p.git_blob(BASE, PLAN), p.git_blob(SOURCE, PLAN)
    need(new_plan.endswith(old_plan) and len(new_plan) > len(old_plan), 'sole plan suffix changed')
    prepend = new_plan[:-len(old_plan)]
    need(prepend.endswith(b'\n\n') and sha(prepend[:-1]) == PLAN_ENTRY_SHA, 'plan prepend changed')
    original = p.strict_json(p.git_blob(BASE, CORPUS))
    expected = copy.deepcopy(original)
    for name in (*POST_SHA, PLAN):
        need(name in original['required_paths'] and original['pinned_blobs'][name] == before[name][1],
             'original source corpus pin differs')
        expected['pinned_blobs'][name] = after[name][1]
    need(p.strict_json(p.git_blob(SOURCE, CORPUS)) == expected, 'source corpus changed outside three pins')
    return before, after


def wait_finished():
    deadline = time.monotonic() + 21600
    while True:
        no_hold()
        if os.path.lexists(OUT / 'VALIDATION_FINISHED.json'):
            return p.read_small(OUT / 'VALIDATION_FINISHED.json', scan=True)
        need(time.monotonic() < deadline, 'native FINISHED not available within fixed wait')
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def text_lines(blocks):
    """Bound line memory; exhaust all chunks so fd and whole-file identity checks run."""
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    pending = ''
    bad = False
    for block in blocks:
        if bad:
            continue
        try:
            value = decoder.decode(block)
        except UnicodeError:
            bad = True
            continue
        parts = value.split('\n')
        for number, part in enumerate(parts):
            if number:
                yield pending
                pending = ''
            pending += part
            if len(pending) > 1024 * 1024:
                bad = True
                pending = ''
                break
    if not bad:
        try:
            pending += decoder.decode(b'', final=True)
        except UnicodeError:
            bad = True
    if pending:
        yield pending
    if bad:
        yield '\x00INVALID_UTF8_OR_OVERSIZED_LINE'


def observe_package(blocks, exit_code):
    """Observe every libtest block in the full package, retaining failures and incomplete blocks."""
    start = re.compile(r'^running (\d+) tests?$')
    test = re.compile(r'^test (.+) \.\.\. (ok|FAILED|ignored(?:, .*)?)$')
    end = re.compile(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                     r'(\d+) measured; (\d+) filtered out; finished in .+$')
    groups, active, errors = [], None, []
    observed = {name: [] for name in SOCKET_NAMES}
    for line in text_lines(blocks):
        if line.startswith('\x00'):
            errors.append('invalid log encoding or oversized line')
        a, b, c = start.fullmatch(line), test.fullmatch(line), end.fullmatch(line)
        if a:
            if active is not None:
                errors.append('new test block before previous summary')
            active = {'declared': int(a[1]), 'tests': []}
        elif b and active is not None:
            name, result = b.groups()
            result = 'ignored' if result.startswith('ignored') else result
            active['tests'].append((name, result))
            if name in observed:
                observed[name].append(result)
        elif c:
            if active is None:
                errors.append('summary without running header')
                continue
            status, *values = c.groups()
            counts = list(map(int, values))
            tests = active['tests']
            actual = [sum(result == label for _, result in tests) for label in ('ok', 'FAILED', 'ignored')]
            consistent = (len(tests) == len(set(name for name, _ in tests)) == active['declared']
                          and actual == counts[:3] and sum(counts[:4]) == active['declared'])
            groups.append({'declared': active['declared'], 'status': status,
                           'counts': dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), counts)),
                           'observed_test_lines': len(tests), 'consistent': consistent})
            active = None
    if active is not None:
        errors.append('unfinished test block')
    if not groups:
        errors.append('no complete libtest summaries')
    success = (exit_code == 0 and not errors and all(group['consistent'] and group['status'] == 'ok'
               and all(group['counts'][key] == 0 for key in ('failed', 'ignored', 'measured', 'filtered_out'))
               for group in groups) and all(values == ['ok'] for values in observed.values()))
    return {'complete_success': success, 'blocks': groups, 'socket_tests': observed,
            'parse_errors': errors, 'scope': 'full trnm-checkpoint-store package on the new source'}


def observe_source_controls(blocks, exit_code):
    rows, counts, endings = [], [], []
    for line in text_lines(blocks):
        if re.fullmatch(r'test_[^ ]+ \(.+\) \.\.\. ok', line):
            rows.append(line)
        match = re.fullmatch(r'Ran (\d+) tests? in [0-9.]+s', line)
        if match:
            counts.append(int(match[1]))
        if line in ('OK', 'FAILED') or line.startswith('FAILED (') or line.startswith('\x00'):
            endings.append(line)
    return {'complete_success': exit_code == 0 and counts == [43] and endings == ['OK']
            and len(rows) == len(set(rows)) == 43, 'summary_counts': counts,
            'observed_success_lines': len(rows), 'ending_status': endings}


def observe_bound_file(name, expected, parser, exit_code):
    digest, count = hashlib.sha256(), 0
    def blocks():
        nonlocal count
        for block in p.chunks(OUT / name):
            digest.update(block)
            count += len(block)
            yield block
    result = parser(blocks(), exit_code)
    need({'bytes': count, 'sha256': digest.hexdigest()} == expected, 'parsed log changed: ' + name)
    return result


def validate_preparation(snapshot):
    frozen_raw = p.read_small(CONTROL / 'FROZEN.json', scan=True)
    need(frozen_raw == snapshot, 'source preparation differs from original validation snapshot')
    need(identity(frozen_raw) == {'bytes': PREPARATION['frozen_bytes'], 'sha256': PREPARATION['frozen_sha256']},
         'source preparation original is not the independently pinned FROZEN')
    frozen = p.strict_json(frozen_raw)
    need(frozen['schema'] == 'checkpoint-probe-source-v1' and frozen['operation_key'] == PREP_KEY
         and frozen['head'] == SOURCE and frozen['tree'] == TREE and frozen['parent'] == BASE
         and frozen['parent_tree'] == BASE_TREE and frozen['worktree'] == str(ROOT)
         and frozen['branch'] == BRANCH and frozen['program_sha256'] == SOURCE_PREP_SHA,
         'source preparation identity mismatch')
    need(frozen['input_sha256'] == PREPARATION['input_sha256']
         and frozen['safe_manifest_sha256'] == PREPARATION['safe_manifest_sha256'], 'preparation input/manifest pin changed')
    for name in ('unchanged_outside_four_paths', 'source_clean', 'shared_config_unchanged', 'old_source_head_unchanged'):
        need(frozen[name] is True, 'source preparation integrity not established')
    for name in ('old_failures_reused_as_new_pass', 'native_tests_executed', 'publication_performed', 'production_activation'):
        need(frozen[name] is False, 'source preparation overclaims')
    need(frozen['status'] == 'HOLD' and frozen['prior_root_source'] == OLD_SOURCE
         and frozen['allowed_corpus_pin_paths'] == [*POST_SHA, PLAN], 'source preparation scope differs')
    parent = frozen['parent_pr']
    need(parent['number'] == BASE_PR and parent['headRefOid'] == BASE and parent['headRefName'] == BASE_BRANCH
         and parent['author_login'] == 'ProfHepta' and parent['state'] == 'OPEN' and parent['isDraft'] is True,
         'source preparation parent PR differs')
    safe_raw = p.read_small(CONTROL / 'SAFE_MANIFEST.json', scan=True)
    need(sha(safe_raw) == frozen['safe_manifest_sha256'], 'safe source-preparation manifest changed')
    safe = p.strict_json(safe_raw)
    need(safe['schema'] == 'checkpoint-probe-source-safe-manifest-v1' and safe['source'] == SOURCE
         and safe['tree'] == TREE and safe['parent_evidence'] == BASE, 'safe manifest identity differs')
    files, preparation_bytes = {}, {}
    for row in safe['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and row['path'] in SAFE_PREP and row['path'] not in files, 'unreviewed source preparation archive path')
        expected = {'bytes': row['bytes'], 'sha256': row['sha256']}
        value = p.read_small(CONTROL / row['path'], scan=True)
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= CAP and p.digest_ok(row['sha256'])
             and identity(value) == expected, 'safe preparation bytes differ')
        files[row['path']] = expected
        preparation_bytes[row['path']] = value
    need(set(files) == SAFE_PREP and files['driver.py']['sha256'] == SOURCE_PREP_SHA,
         'safe preparation roster differs')
    delta = p.strict_json(preparation_bytes['FOUR_PATH_DELTA.json'])
    need(delta == frozen['four_path_delta'] and len(delta) == 4, 'preparation delta differs')
    before, after = p.entries(BASE), p.entries(SOURCE)
    need({row['path'] for row in delta} == {*POST_SHA, PLAN, CORPUS}, 'preparation delta paths differ')
    for row in delta:
        name = row['path']
        need((row['old_mode'], row['old_blob'], row['old_bytes']) == before[name]
             and (row['new_mode'], row['new_blob'], row['new_bytes']) == after[name]
             and row['old_sha256'] == sha(p.git_blob(BASE, name))
             and row['new_sha256'] == sha(p.git_blob(SOURCE, name)), 'preparation full delta identity differs')
    for label in ('BEFORE_EDIT', 'STAGED', 'COMMITTED'):
        receipt = p.strict_json(preparation_bytes['PREFLIGHT_' + label + '.receipt.json'])
        argv = ['bash', 'scripts/project-preflight.sh'] + (['--staged'] if label == 'STAGED' else [])
        need(receipt['argv'] == argv and receipt['cwd'] == str(ROOT)
             and receipt['timeout_seconds'] == 120 and receipt['exit_code'] == 0
             and receipt['timed_out'] is False, 'source-preparation preflight differed or failed')
        for stream in ('stdout', 'stderr'):
            need(receipt[stream + '_sha256'] == files['PREFLIGHT_' + label + '.' + stream]['sha256'],
                 'source-preparation preflight output differs')
    return frozen, [(CONTROL / name, 'source-preparation/' + name, value) for name, value in sorted(files.items())] + [
        (CONTROL / 'FROZEN.json', 'source-preparation/FROZEN.json', identity(frozen_raw)),
        (CONTROL / 'SAFE_MANIFEST.json', 'source-preparation/SAFE_MANIFEST.json', identity(safe_raw)),
    ]


def checked_prior(read_bound):
    closure = p.strict_json(read_bound('prior-owner-closure.json'))
    need(set(closure) == {'schema', 'validation', 'publication', 'publication_receipt'}
         and closure['schema'] == 'checkpoint-probe-prior-owner-closure-v1', 'prior owner projection differs')
    for name, job, key, runtime_key in (
        ('validation', '1a1cf53f912-2564-19f0', 'root-operation-20261112-df05-native-validation-v3',
         'root-operation-20261112-df05-native-validation-v3'),
        ('publication', '1a1cfcc92d8-2564-1aba', 'root-operation-20261112-df05-native-publication-v2',
         'root-operation-20261112-df05-native-publication-v2-resume1'),
    ):
        need(closure[name] == {'job_id': job, 'operation_key': key, 'runtime_idempotency_key': runtime_key,
             'state': 'succeeded', 'exit_code': 0,
             'output_complete': True, 'output_durable': True, 'terminal_publication_confirmed': True},
             'prior native owner terminal remains unconfirmed')
        need(type(closure[name]['exit_code']) is int and all(closure[name][field] is True
             for field in ('output_complete', 'output_durable', 'terminal_publication_confirmed')),
             'prior native owner terminal types differ')
    prior_raw = read_bound('prior-publication-receipt.json')
    need(closure['publication_receipt'] == PARENT_PUBLICATION_RECEIPT == identity(prior_raw),
         'prior publication receipt identity differs')
    prior = p.strict_json(prior_raw)
    need(prior['operation_key'] == 'root-operation-20261112-df05-native-publication-v2'
         and prior['native_source'] == OLD_SOURCE and prior['native_tree'] == OLD_TREE
         and prior['evidence_commit'] == BASE and prior['pr'] == 'https://github.com/' + REPO + '/pull/945'
         and prior['publication_complete'] is True and prior['draft'] is True and prior['status'] == 'HOLD'
         and prior['native_all_commands_passed'] is False and prior['supplement_complete_success'] is False
         and prior['production_activation'] is False, 'prior qualification was relabelled')
    for name, archived in (
        ('prior-environment.json', 'native/environment.json'),
        ('prior-validation-finished.json', 'native/VALIDATION_FINISHED.json'),
        ('prior-socket-finished.json', 'supplemental/FINISHED.json'),
    ):
        need(read_bound(name) == p.git_blob(BASE, OLD_PREFIX + '/' + archived), 'prior receipt is not its exact E1 original')
    old_env = p.strict_json(read_bound('prior-environment.json'))
    need(old_env['source'] == OLD_SOURCE and old_env['tree'] == OLD_TREE, 'prior environment source differs')
    selected = selected_environment()
    need(set(old_env['environment']) == set(selected) and all(
         old_env['environment'][name] == value for name, value in selected.items()
         if name not in ('CARGO_TARGET_DIR', 'TMPDIR', 'PYTHONPYCACHEPREFIX')),
         'native profile or resource environment changed beyond the explicit fresh storage paths')
    need(old_env['environment']['CARGO_TARGET_DIR'] == PRIOR_TARGET,
         'recorded original target pathname changed')
    socket = p.strict_json(read_bound('prior-socket-finished.json'))
    need(socket['binding']['source'] == OLD_SOURCE and socket['execution']['exit_code'] == 101
         and socket['execution']['source_verified'] is True and socket['execution']['timed_out'] is False
         and socket['observation']['complete_success'] is False, 'historical socket failure changed')


def validate_fresh_target_admission(env_document, target_id):
    admission = env_document['target_admission']
    need(admission['path'] == str(TARGET) and admission['identity'] == target_id
         and admission['prior_environment_target'] == PRIOR_TARGET,
         'fresh target admission identity differs')
    need(all(admission[name] is True for name in (
         'created_new_empty', 'absent_before_creation', 'parent_identity_unchanged_during_creation'))
         and admission['old_target_reused'] is False and admission['old_target_recreated'] is False,
         'fresh target admission was relabelled as reuse or repair')
    need(type(admission['parent_device']) is int and admission['parent_device'] >= 0
         and type(admission['parent_inode']) is int and admission['parent_inode'] > 0,
         'fresh target parent identity missing')
    need(admission['requested_mode'] == 0o700 and admission['creating_euid'] == target_id['uid'] == os.geteuid()
         and admission['required_free_bytes'] == 10 * 1024 ** 3
         and admission['output_required_free_bytes'] == 1024 ** 3
         and type(admission['free_bytes_before_creation']) is int
         and admission['free_bytes_before_creation'] >= admission['required_free_bytes']
         and type(admission['output_free_bytes_before_creation']) is int
         and admission['output_free_bytes_before_creation'] >= admission['output_required_free_bytes'],
         'new target creation weakened original storage or ownership admission')
    need(env_document['minimum_free_bytes_before_command'] == 10 * 1024 ** 3
         and type(env_document['before_target_disk']['free']) is int
         and env_document['before_target_disk']['free'] >= 10 * 1024 ** 3
         and type(env_document['before_output_disk']['free']) is int
         and env_document['before_output_disk']['free'] >= 1024 ** 3,
         'original native disk reserve admission changed')


def validate_prior_admission_failure(raw):
    need(identity(raw) == PRIOR_VALIDATION_FAILURE, 'original validation-v1 failure bytes changed')
    failure = p.strict_json(raw)
    need(failure['operation_key'] == 'chain-checkpoint-probe-native-validation-20261112-df05-v1'
         and failure['stage'] == 'admit-prior-owners-before-target-reuse'
         and failure['error_type'] == 'FileNotFoundError'
         and PRIOR_TARGET in failure['error']
         and type(failure['records_completed']) is int and failure['records_completed'] == 0
         and failure['no_success_inferred'] is True,
         'historical admission failure changed scope')
    return failure


def validate_prior_invocation(raw):
    need(identity(raw) == PRIOR_VALIDATION_INVOCATION, 'original validation-v1 invocation bytes changed')
    invocation = p.strict_json(raw)
    need(invocation['operation_key'] == 'chain-checkpoint-probe-native-validation-20261112-df05-v1'
         and invocation['source'] == SOURCE and invocation['tree'] == TREE
         and invocation['parent_evidence'] == BASE and invocation['parent_tree'] == BASE_TREE
         and invocation['driver_sha256'] == '2230d33d86dd0ae5d5055fb38d511a53748a160ae134e0ffcd271c858d38895c'
         and invocation['input_sha256'] == 'a2a39dac59945a3009a7ade6cbe043b790bf0c4b485c69f95e2fc7fc504c22b2',
         'original validation-v1 source identity changed')
    return invocation


def validate_native(finished_raw):
    no_hold()
    finished = p.strict_json(finished_raw)
    need(set(finished) == {'schema', 'operation_key', 'source', 'tree', 'parent_evidence',
                          'manifest_sha256', 'summary_sha256', 'all_commands_passed', 'status', 'publication_performed'},
         'FINISHED fields differ')
    need(finished['schema'] == 'checkpoint-probe-native-finished-v1' and finished['operation_key'] == RUN_KEY
         and finished['source'] == SOURCE and finished['tree'] == TREE and finished['parent_evidence'] == BASE
         and finished['status'] == 'HOLD' and finished['publication_performed'] is False, 'FINISHED identity or scope differs')
    manifest_raw = p.read_small(OUT / 'ARTIFACT_MANIFEST.json', scan=True)
    summary_raw = p.read_small(OUT / 'SUMMARY.json', scan=True)
    need(sha(manifest_raw) == finished['manifest_sha256'] and sha(summary_raw) == finished['summary_sha256'],
         'FINISHED does not bind exact native metadata')
    manifest, summary = p.strict_json(manifest_raw), p.strict_json(summary_raw)
    need(set(manifest) == {'source', 'tree', 'parent_evidence', 'artifacts'} and manifest['source'] == SOURCE
         and manifest['tree'] == TREE and manifest['parent_evidence'] == BASE, 'manifest schema/source differs')
    plan = planned_commands()
    required = BASE_ARTIFACTS | {name + suffix for name, _, _ in plan for suffix in ('.log', '.receipt.json')}
    artifacts = {}
    for row in manifest['artifacts']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'artifact row fields differ')
        name = str(p.relative(row['path']))
        need(name in required and name not in artifacts and type(row['bytes']) is int and row['bytes'] >= 0
             and p.digest_ok(row['sha256']), 'unreviewed native artifact')
        expected = {'bytes': row['bytes'], 'sha256': row['sha256']}
        need(p.file_identity(OUT / name, scan=True) == expected, 'native artifact bytes changed: ' + name)
        artifacts[name] = expected
    need(set(artifacts) == required, 'incomplete native artifact roster')
    found = set()
    for entry in os.scandir(OUT):
        need(not entry.is_symlink(), 'native artifact symlink')
        if entry.name in ('tmp', 'pycache'):
            need(entry.is_dir(follow_symlinks=False), 'temporary output is not a directory')
            continue
        need(entry.is_file(follow_symlinks=False), 'unreviewed native subdirectory or special file')
        found.add(entry.name)
    need(found == required | {'ARTIFACT_MANIFEST.json', 'VALIDATION_FINISHED.json'}, 'extra native output path')
    def read_bound(name):
        raw = p.read_small(OUT / name, scan=True)
        need(identity(raw) == artifacts[name], 'native metadata changed after inventory: ' + name)
        return raw
    need(identity(summary_raw) == artifacts['SUMMARY.json'] and artifacts['driver.py']['sha256'] == DRIVER_SHA,
         'unreviewed native driver or summary')
    invocation = p.strict_json(read_bound('invocation.json'))
    need(invocation['operation_key'] == RUN_KEY and invocation['source'] == SOURCE and invocation['tree'] == TREE
         and invocation['parent_evidence'] == BASE and invocation['parent_tree'] == BASE_TREE
         and invocation['driver_sha256'] == DRIVER_SHA and invocation['input_sha256'] == DRIVER_INPUT_SHA,
         'native invocation differs from reviewed input')
    frozen, preparation_files = validate_preparation(read_bound('source-preparation.json'))
    checked_prior(read_bound)
    env_document = p.strict_json(read_bound('environment.json'))
    selected = selected_environment()
    need(env_document['source'] == SOURCE and env_document['tree'] == TREE and env_document['parent_evidence'] == BASE
         and env_document['environment'] == selected and env_document['optimization_or_debug_profile_overrides'] is False
         and env_document['isolated_new_target'] is True
         and env_document['reused_target_after_verified_prior_owner_terminal'] is False,
         'native environment was substituted')
    target_id = env_document['target_identity']
    need(set(target_id) == {'device', 'inode', 'mode', 'uid', 'gid'}
         and all(type(value) is int and value >= 0 for value in target_id.values())
         and target_id['inode'] > 0 and target_id['mode'] == 0o700 and target_id['uid'] == os.geteuid()
         and env_document['target_identity_rechecked_per_command'] is True,
         'native target identity not bound')
    validate_fresh_target_admission(env_document, target_id)
    target = TARGET.lstat()
    need(stat.S_ISDIR(target.st_mode) and target_id == {'device': target.st_dev, 'inode': target.st_ino,
         'mode': stat.S_IMODE(target.st_mode), 'uid': target.st_uid, 'gid': target.st_gid},
         'native target incarnation changed after validation')
    provider = env_document['provider']
    need(type(provider) is list and len(provider) == len(PROVIDER_HASHES), 'provider inventory differs')
    seen = set()
    for row in provider:
        need(set(row) == {'path', 'bytes', 'sha256'} and type(row['bytes']) is int, 'provider record differs')
        name = str(Path(row['path']).relative_to(PROVIDER))
        need(name in PROVIDER_HASHES and name not in seen and row['sha256'] == PROVIDER_HASHES[name]
             and p.file_identity(Path(row['path']), allow_hardlinks=True) == {'bytes': row['bytes'], 'sha256': row['sha256']},
             'provider original changed')
        seen.add(name)
    actual_plan = p.strict_json(read_bound('plan.json'))
    need(actual_plan['source'] == SOURCE and actual_plan['tree'] == TREE and actual_plan['parent_evidence'] == BASE
         and actual_plan['commands'] == [{'name': name, 'argv': argv, 'outer_timeout_seconds': timeout}
                                         for name, argv, timeout in plan]
         and actual_plan['original_test_and_internal_transport_timeouts_unchanged'] is True
         and actual_plan['root_s879_native_qualification_reused'] is False, 'original gate plan or budgets changed')
    before, after = (p.strict_json(read_bound(name)) for name in ('source-before.json', 'source-after.json'))
    need(before == after and before['tested_commit'] == SOURCE and before['tested_tree'] == TREE
         and before['candidate'] == SOURCE and before['kind'] == 'head' and before['tracked_worktree_verified'] is True,
         'native source verifier receipts disagree')
    physical_before, physical_after = (p.strict_json(read_bound(name)) for name in ('physical-before.json', 'physical-after.json'))
    need(physical_before == physical_after and physical_before['commit'] == SOURCE and physical_before['tree'] == TREE
         and physical_before['physical_bytes_checked'] is True, 'native physical tree receipts disagree')
    rows = p.strict_json(read_bound('commands.json'))
    need(type(rows) is list and len(rows) == len(plan) and rows == summary['commands'], 'native command inventory differs')
    for row, (name, argv, _) in zip(rows, plan):
        need(row['name'] == name and row['command'] == argv and row['cwd'] == str(ROOT)
             and row['source'] == SOURCE and row['expected_source'] == SOURCE and row['executed'] is True
             and row['source_verified'] is True and row['source_before_verified'] is True
             and row['source_after_verified'] is True, 'native command/source integrity differs')
        need(type(row['exit_code']) is int and type(row['timed_out']) is bool
             and type(row['process_exit_code']) is int and type(row['elapsed_ns']) is int and row['elapsed_ns'] >= 0
             and row['exit_code'] == (124 if row['timed_out'] else row['process_exit_code'])
             and row['log'] == name + '.log', 'native outcome was relabelled')
        need(row == p.strict_json(read_bound(name + '.receipt.json'))
             and artifacts[row['log']] == {'bytes': row['bytes'], 'sha256': row['sha256']},
             'native receipt/log identity mismatch')
        need(row['target_before_identity'] == target_id == row['target_after_identity']
             and row['target_identity_error'] is None, 'native target changed across command')
    passed = all(row['exit_code'] == 0 and not row['timed_out'] for row in rows)
    need(summary['schema'] == 'checkpoint-probe-native-validation-v1' and summary['operation_key'] == RUN_KEY
         and summary['source'] == SOURCE and summary['tree'] == TREE and summary['parent_evidence'] == BASE
         and summary['parent_tree'] == BASE_TREE and summary['source_consistent'] is True
         and summary['provider_unchanged'] is True and summary['target_identity_consistent'] is True
         and summary['status'] == 'HOLD', 'native summary identity/integrity differs')
    need(summary['all_commands_passed'] is passed and finished['all_commands_passed'] is passed
         and all(summary[name] is False for name in ('root_s879_native_qualification_reused', 'production_activation', 'publication_performed')),
         'native summary overclaims')
    by_name = {row['name']: row for row in rows}
    package = observe_bound_file('checkpoint-package.log', artifacts['checkpoint-package.log'],
                                 observe_package, by_name['checkpoint-package']['exit_code'])
    controls = observe_bound_file('source-integrity-controls.log', artifacts['source-integrity-controls.log'],
                                  observe_source_controls, by_name['source-integrity-controls']['exit_code'])
    qualification = {'all_original_commands_passed': passed, 'checkpoint_package': package,
                     'source_integrity_controls': controls,
                     'native_scope_pass': passed and package['complete_success'] and controls['complete_success'],
                     'old_root_s879_results_relabelled': False, 'whole_chain_pq_qualified': False,
                     'arm_verified': False, 'prospective_merge_verified': False,
                     'original_three_30s_campaigns_verified': False, 'production_activation': False,
                     'status': 'HOLD'}
    candidates = [(OUT / name, 'native/' + name, item) for name, item in sorted(artifacts.items())]
    candidates += [(OUT / 'ARTIFACT_MANIFEST.json', 'native/ARTIFACT_MANIFEST.json', identity(manifest_raw)),
                   (OUT / 'VALIDATION_FINISHED.json', 'native/VALIDATION_FINISHED.json', identity(finished_raw))]
    need(p.read_small(OUT / 'VALIDATION_FINISHED.json') == finished_raw, 'FINISHED changed during validation')
    return finished, summary, selected, provider, qualification, candidates + preparation_files


def safe_history():
    refusal = Path('/data/chain-root-publication-20261112-df05-v2/refusal-1794486328696499756.json')
    staged = Path('/data/chain-root-publication-staging-recovery-20261112-df05-v1/STAGED.json')
    originals = [(refusal, 'prior-publication/original-staging-refusal.json',
                  {'bytes': 238, 'sha256': '6e4a705932b6049a5fd27ab68d0fbbd60d1076045756c1864f6cf9fb7d7cf0f2'}),
                 (staged, 'prior-publication/STAGED.json', STAGED_IDENTITY),
                 (PRIOR_VALIDATION_OUT / 'FAILED.json', 'prior-validation-v1/FAILED.json', PRIOR_VALIDATION_FAILURE),
                 (PRIOR_VALIDATION_OUT / 'invocation.json', 'prior-validation-v1/invocation.json', PRIOR_VALIDATION_INVOCATION)]
    snapshots = {}
    for path, _, expected in originals:
        value = p.read_small(path, scan=True)
        need(identity(value) == expected, 'safe historical original changed')
        snapshots[path] = value
    record = p.strict_json(snapshots[staged])
    need(record['source'] == OLD_SOURCE and record['ignored_logs_staged'] == 62 and record['sealed_files'] == 167
         and record['tracked_source_index_unchanged'] is True and record['worktree_payload_mutation_performed'] is False
         and record['commit_push_pr_performed'] is False and record['tests_rerun'] is False
         and record['source_or_test_qualification_changed'] is False, 'staging recovery scope differs')
    validate_prior_admission_failure(snapshots[PRIOR_VALIDATION_OUT / 'FAILED.json'])
    validate_prior_invocation(snapshots[PRIOR_VALIDATION_OUT / 'invocation.json'])
    return originals


def publication_binding(finished_raw, program):
    finished = p.strict_json(finished_raw)
    return {'schema': 'checkpoint-probe-publication-intent-v1', 'operation_key': PUB_KEY,
            'source': SOURCE, 'source_tree': TREE, 'parent_evidence': BASE, 'parent_tree': BASE_TREE,
            'base_pr': BASE_PR, 'base_branch': BASE_BRANCH, 'branch': BRANCH, 'repository': REPO,
            'validation_operation_key': RUN_KEY, 'validation_directory': str(OUT),
            'validation_driver_sha256': DRIVER_SHA, 'validation_input_sha256': DRIVER_INPUT_SHA,
            'native_manifest_sha256': finished['manifest_sha256'], 'native_summary_sha256': finished['summary_sha256'],
            'native_finished_sha256': sha(finished_raw), 'publisher_sha256': sha(program),
            'helper_sha256': HELPER_SHA, 'source_preparation_program_sha256': SOURCE_PREP_SHA,
            'source_preparation': PREPARATION,
            'parent_publication_receipt': PARENT_PUBLICATION_RECEIPT, 'staging_recovery_receipt': STAGED_IDENTITY,
            'prior_validation_failure': PRIOR_VALIDATION_FAILURE,
            'prior_validation_invocation': PRIOR_VALIDATION_INVOCATION,
            'fresh_target': str(TARGET), 'prior_target_reused': False}


def seal(binding, finished_raw, summary, qualification, candidates, program, helper_raw):
    no_hold()
    write_json(STATE / 'PUBLICATION_INTENT.json', binding)
    if os.path.lexists(STATE / 'SEALED.json'):
        return p.checked_sealed(binding)
    p.physical_tree(SOURCE)
    p.repo_verify(SOURCE)
    folder = STATE / 'sealed'
    originals, expected_paths = [], set()
    candidates = candidates + safe_history()
    need(len({name for _, name, _ in candidates}) == len(candidates), 'duplicate archival identity')
    for index, (path, name, expected) in enumerate(candidates):
        p.relative(name)
        need(p.file_identity(path, scan=True) == expected, 'original changed before sealing: ' + name)
        parts, digest, size = [], hashlib.sha256(), 0
        for number, block in enumerate(p.chunks(path)):
            destination = name if expected['bytes'] <= CAP else f'parts/{index:05d}/{number:06d}.bin'
            need(destination not in expected_paths and len(block) <= CAP, 'archive part collision or cap')
            write(folder / destination, block)
            expected_paths.add(destination)
            parts.append({'path': destination, **identity(block)})
            digest.update(block)
            size += len(block)
        if expected['bytes'] == 0:
            need(name not in expected_paths, 'empty archive collision')
            write(folder / name, b'')
            expected_paths.add(name)
            parts = [{'path': name, **identity(b'')}]
        need({'bytes': size, 'sha256': digest.hexdigest()} == expected, 'original changed while sealing')
        originals.append({'original_path': name, **expected, 'parts': parts})
    payloads = {
        'publisher.py': program,
        'audited-helper.py': helper_raw,
        'SOURCE_QUALIFICATION.json': p.canonical(qualification),
        'PUBLICATION_PACKAGE.json': p.canonical({
            'schema': 'checkpoint-probe-publication-package-v1', 'binding': binding,
            'native_commands': summary['commands'], 'qualification': qualification, 'originals': originals,
            'chunk_byte_cap': CAP, 'raw_original_bytes_preserved': True,
            'prior_runtime_closure_basis': 'controller-pinned authoritative terminal projection; not a claim inferred from GitHub',
            'old_root_source': OLD_SOURCE, 'old_root_tree': OLD_TREE,
            'root_s879_suite_results_relabelled': False, 'private_sdk_input_or_indexes_included': False,
            'archive_scope': 'fixed manifest-bound native output, sixteen safe preparation files, and four safe historical receipts',
            'prior_validation_admission_failure_preserved': True,
            'prior_validation_v1_command_records': 0, 'prior_target_reused_or_recreated': False,
            'status': 'HOLD', 'production_activation': False,
        }),
        'README.md': (
            '# Checkpoint socket probe follow-up — Draft HOLD\n\n'
            f'Tested source: {SOURCE}\n\nSource tree: {TREE}\n\n'
            f'Parent evidence commit: {BASE} (Root Draft #{BASE_PR}).\n\n'
            'The source change removes the redundant accept-time socket-owner check. A bounded complete request '
            'still reaches the original pathname fence before checkpoint export, lookup, compare-and-advance or any response. '
            'All three original socket tests remain unchanged; one complete-request negative control is added.\n\n'
            '[Native summary](native/SUMMARY.json), [original command receipts](native/commands.json), '
            '[source qualification](SOURCE_QUALIFICATION.json), [ordered original-byte manifest](PUBLICATION_PACKAGE.json), '
            '[source preparation](source-preparation/FROZEN.json).\n\n'
            'Only the fourteen listed commands ran on this new source. The complete checkpoint package uses the original '
            '1200-second outer limit, original transport bounds and test-thread setting. Every command exit and timeout remains visible. '
            'The original Root V3/V4/V5/V6 results remain attached to the earlier source ' + OLD_SOURCE + '. '
            'They were not rerun by this follow-up and are not qualifications of this new source.\n\n'
            'The evidence commit is a sole archival child of the tested source. It is not another execution. '
            'Files larger than the unchanged 4 MiB corpus cap are retained in ordered parts with whole-original length and SHA-256.\n\n'
            'The old ignored-log staging refusal and narrowly scoped recovery receipt remain under prior-publication. '
            'The first socket validation attempt stopped during admission because the recorded old target directory '
            'was absent. Its unchanged FAILED.json, including the original traceback and zero completed command records, '
            'is retained under prior-validation-v1. The current attempt creates a different empty private target; '
            'it neither recreates nor reuses the missing old target. The fourteen original command arguments and '
            'limits are unchanged. This archived failure receipt is not a qualification or a runtime-owner terminal proof. '
            'Private native SDK records, input bodies and Git indexes are excluded.\n\n'
            'This remains Draft HOLD. ARM, prospective GitHub merge validation, the original three 30-second campaigns, '
            'whole-chain post-quantum qualification, independent authority custody, actual external effects and production activation '
            'are not certified by these observations.\n'
        ).encode(),
    }
    for name, value in payloads.items():
        need(name not in expected_paths and len(value) <= CAP, 'publication metadata collision or cap')
        write(folder / name, value)
        expected_paths.add(name)
    files = {}
    for directory, dirs, names in os.walk(folder, followlinks=False):
        for name in dirs:
            need(not (Path(directory) / name).is_symlink(), 'symlinked seal directory')
        for name in names:
            path = Path(directory) / name
            relative = str(p.relative(path.relative_to(folder).as_posix()))
            need(relative in expected_paths, 'unexpected partial seal artifact')
            item = p.file_identity(path, scan=True)
            need(item['bytes'] <= CAP, 'unchanged corpus cap exceeded')
            files[relative] = item
    need(set(files) == expected_paths, 'incomplete seal')
    no_hold()
    need(p.read_small(OUT / 'VALIDATION_FINISHED.json') == finished_raw, 'FINISHED changed before sealing')
    write_json(STATE / 'SEALED.json', {'binding': binding, 'files': files})
    return p.checked_sealed(binding)


def check_archive_tree(revision, sealed, corpus):
    before, after = p.entries(SOURCE), p.entries(revision)
    additions = {PREFIX + '/' + name for name in sealed['files']}
    need(not additions & set(before) and set(after) == set(before) | additions, 'archive path set differs')
    for name, value in before.items():
        expected = ('100644', p.blob_id(corpus), len(corpus)) if name == CORPUS else value
        need(after[name] == expected, 'archive changed existing source or mode: ' + name)
    for name, expected in sealed['files'].items():
        value = p.read_small(STATE / 'sealed' / name)
        need(identity(value) == expected and after[PREFIX + '/' + name] == ('100644', p.blob_id(value), len(value)),
             'archive staged blob/mode differs')


def worktree_archive(sealed, corpus):
    p.physical_tree(SOURCE, dirty_evidence=True,
                    overrides={CORPUS: (p.git_blob(SOURCE, CORPUS), corpus)},
                    evidence_paths={PREFIX + '/' + name for name in sealed['files']})
    for name, expected in sealed['files'].items():
        path = ROOT / PREFIX / name
        if os.path.lexists(path):
            need(p.file_identity(path, scan=True) == expected, 'worktree archive bytes differ')


def archive_commit(sealed, selected):
    no_hold()
    corpus = p.expected_corpus(SOURCE, sealed)
    current = p.gtext('rev-parse', 'HEAD')
    if current != SOURCE:
        p.permitted_delta(SOURCE, current, sealed, corpus)
        p.physical_tree(current)
        write_json(STATE / 'EVIDENCE_COMMIT.json', {'source': SOURCE, 'evidence': current,
                   'tree': p.gtext('rev-parse', current + '^{tree}')})
        return current
    worktree_archive(sealed, corpus)
    publication_preflight(current)
    p.command(['bash', 'scripts/project-preflight.sh'], env=selected)
    for name, expected in sealed['files'].items():
        raw = p.read_small(STATE / 'sealed' / name)
        need(identity(raw) == expected, 'sealed bytes changed before worktree copy')
        write(ROOT / PREFIX / name, raw)
        p.archive_mode(ROOT / PREFIX / name)
    previous = p.git_blob(SOURCE, CORPUS)
    existing = p.read_small(ROOT / CORPUS)
    need(existing in (previous, corpus), 'corpus has an unrelated edit')
    if existing != corpus:
        temporary = ROOT / (CORPUS + '.checkpoint-evidence.tmp')
        write(temporary, corpus)
        need(p.read_small(ROOT / CORPUS) == previous, 'corpus changed before replacement')
        os.replace(temporary, ROOT / CORPUS)
        p.archive_mode(ROOT / CORPUS)
        p.fsync_directory((ROOT / CORPUS).parent)
    no_hold()
    evidence_paths = [PREFIX + '/' + name for name in sorted(sealed['files'])]
    # *.log is intentionally ignored by the existing repository. Force only the
    # immutable, explicit archive allowlist, never a directory, glob, or add -A.
    for offset in range(0, len(evidence_paths), 100):
        p.git(*INDEX, 'add', '--force', '--', *evidence_paths[offset:offset + 100])
    p.git(*INDEX, 'add', '--', CORPUS)
    staged = set(p.git('diff', '--cached', '--name-only', '-z', SOURCE).stdout.decode().split('\0')) - {''}
    need(staged == set(evidence_paths) | {CORPUS}, 'staged archive path allowlist differs')
    candidate = p.gtext('write-tree')
    check_archive_tree(candidate, sealed, corpus)
    worktree_archive(sealed, corpus)
    p.repository_identity()
    p.command(['bash', 'scripts/project-preflight.sh', '--staged'], env=selected)
    need(p.gtext('write-tree') == candidate, 'preflight changed the admitted index')
    marker = STATE / 'EVIDENCE_COMMIT_STARTED.json'
    need(not os.path.lexists(marker), 'earlier commit outcome unresolved at source HEAD; readback only')
    write_json(marker, {'source': SOURCE, 'candidate_tree': candidate,
                       'sealed_sha256': sha(p.read_small(STATE / 'SEALED.json')), 'corpus_sha256': sha(corpus)})
    no_hold()
    p.git(*INDEX, 'commit', '-m', 'test(checkpoint): retain socket probe follow-up evidence with HOLD')
    evidence = p.gtext('rev-parse', 'HEAD')
    need(p.gtext('rev-parse', evidence + '^{tree}') == candidate, 'commit hook changed staged archive')
    p.permitted_delta(SOURCE, evidence, sealed, corpus)
    p.physical_tree(evidence)
    write_json(STATE / 'EVIDENCE_COMMIT.json', {'source': SOURCE, 'evidence': evidence,
               'tree': p.gtext('rev-parse', evidence + '^{tree}')})
    return evidence


def checked_module(name, path, expected):
    raw = p.read_small(path)
    need(sha(raw) == expected, 'reviewed repository module changed: ' + name)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ''
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def final_checks(evidence, selected, sealed):
    p.permitted_delta(SOURCE, evidence, sealed, p.expected_corpus(SOURCE, sealed))
    p.physical_tree(evidence)
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    verifier = checked_module('verify_ci_source', ROOT / 'scripts/ci/verify_ci_source.py', VERIFIER_SHA)
    owner = checked_module('ci_observation', ROOT / 'scripts/ci/ci_observation.py', OWNER_SHA)
    directory = STATE / 'final-source-checks'
    p.ensure_dirs(directory)
    checks = [
        ('preflight', ['bash', 'scripts/project-preflight.sh'], 120),
        ('corpus', ['/usr/bin/python3', '-B', 'scripts/ci/check_pq_research_integration.py'], 600),
        ('links', ['/usr/bin/python3', '-B', 'scripts/ci/check_repository.py'], 600),
        ('inventory', ['/usr/bin/python3', '-B', 'scripts/refresh_distributed_source_inventory.py', '--check'], 300),
    ]
    for name, argv, timeout in checks:
        no_hold()
        log, receipt = directory / (name + '.log'), directory / (name + '.receipt.json')
        if os.path.lexists(receipt):
            row = p.jread(receipt)
        else:
            need(not os.path.lexists(log), 'prior final check outcome unresolved; do not silently rerun')
            row = owner.run(argv, log, timeout=timeout, env=selected, cwd=ROOT, expected_source=evidence)
            row['log_identity'] = p.file_identity(log)
            row['outer_timeout_seconds'] = timeout
            write_json(receipt, row)
        need(row['command'] == argv and row['cwd'] == str(ROOT) and row['expected_source'] == evidence
             and row['exit_code'] == 0 and row['timed_out'] is False and row['executed'] is True
             and row['source_verified'] is True and row['source_before_verified'] is True
             and row['source_after_verified'] is True and row['outer_timeout_seconds'] == timeout
             and row['log_identity'] == p.file_identity(log), 'evidence-child final gate failed or changed')
    p.physical_tree(evidence)
    verifier.verify('head', evidence, root=ROOT)
    p.permitted_delta(SOURCE, evidence, sealed, p.expected_corpus(SOURCE, sealed))


def locate_pr():
    raw = p.gh_command('pr', 'list', '--repo', REPO, '--state', 'all', '--head', BRANCH,
                       '--base', BASE_BRANCH, '--limit', '100', '--json',
                       'number,url,state,isDraft,headRefName,headRefOid,baseRefName,author').stdout
    rows = p.strict_json(raw)
    need(type(rows) is list and len(rows) <= 1, 'ambiguous exact branch/base PR')
    return rows[0] if rows else None


def checked_pr(pr, evidence):
    need(pr['state'] == 'OPEN' and pr['isDraft'] is True and pr['headRefName'] == BRANCH
         and pr['headRefOid'] == evidence and pr['baseRefName'] == BASE_BRANCH
         and pr['author']['login'] == 'ProfHepta'
         and pr['url'] == 'https://github.com/' + REPO + '/pull/' + str(pr['number']),
         'exact PR scope/actor/state differs')


def publication_preflight(current):
    no_hold()
    p.actor()
    p.repository_identity()
    headers = p.git('config', '--get-regexp', r'^http\..*extraheader$', check=False)
    need(headers.returncode == 1 and not headers.stdout, 'Git HTTP extraHeader needs explicit reconciliation')
    parent = p.strict_json(p.gh_command('pr', 'view', str(BASE_PR), '--repo', REPO, '--json',
                          'number,state,isDraft,headRefName,headRefOid,author').stdout)
    need(parent['number'] == BASE_PR and parent['state'] == 'OPEN' and parent['isDraft'] is True
         and parent['headRefName'] == BASE_BRANCH and parent['headRefOid'] == BASE
         and parent['author']['login'] == 'ProfHepta', 'fixed parent Draft moved or changed state')
    need(p.remote_head(BASE_BRANCH) == BASE, 'fixed stacked base moved')
    remote = p.remote_head(BRANCH)
    if remote is not None:
        need(remote == current or (p.git('cat-file', '-e', remote + '^{commit}', check=False).returncode == 0
             and p.git('merge-base', '--is-ancestor', remote, SOURCE, check=False).returncode == 0),
             'remote branch is not absent or an admitted normal ancestor')
    current_pr = locate_pr()
    if current_pr:
        checked_pr(current_pr, remote)


def push(evidence, selected, sealed):
    publication_preflight(evidence)
    observed = p.remote_head(BRANCH)
    if observed == evidence:
        write_json(STATE / 'PUSH_RECEIPT.json', {'source': SOURCE, 'evidence': evidence,
                   'remote_head': observed, 'repository': REPO})
        return
    need(not os.path.lexists(STATE / 'PUSH_ATTEMPT.json'), 'prior push outcome unresolved; readback only')
    if observed is not None:
        need(p.git('merge-base', '--is-ancestor', observed, evidence, check=False).returncode == 0,
             'push would not be a normal fast-forward')
    p.permitted_delta(SOURCE, evidence, sealed, p.expected_corpus(SOURCE, sealed))
    p.physical_tree(evidence)
    p.command(['bash', 'scripts/project-preflight.sh'], env=selected)
    update = f'refs/heads/{BRANCH} {evidence} refs/heads/{BRANCH} {observed or "0" * 40}\n'.encode()
    p.command(['bash', 'scripts/project-preflight.sh', '--push', 'origin', ORIGIN], env=selected, stdin=update)
    write_json(STATE / 'PUSH_ATTEMPT.json', {'operation_key': PUB_KEY, 'source': SOURCE, 'evidence': evidence,
               'observed_old': observed, 'repository': REPO, 'branch': BRANCH, 'no_force': True})
    no_hold()
    helper = '!' + shlex.quote(shutil.which('gh') or 'gh') + ' auth git-credential'
    try:
        result = p.command(['git', '--no-replace-objects', '-c', 'credential.helper=',
                            '-c', 'credential.helper=' + helper, 'push', 'origin',
                            evidence + ':refs/heads/' + BRANCH], timeout=300, check=False)
        write_json(STATE / 'PUSH_COMMAND.json', {'exit_code': result.returncode,
                   'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
    except subprocess.TimeoutExpired:
        write_json(STATE / 'PUSH_COMMAND.json', {'response': 'UNKNOWN', 'no_success_inferred': True})
    actual = p.remote_head(BRANCH)
    need(actual == evidence, 'push not reconciled to exact immutable evidence child; no repeat push')
    write_json(STATE / 'PUSH_RECEIPT.json', {'source': SOURCE, 'evidence': evidence,
               'remote_head': actual, 'repository': REPO})


def pr_body(evidence, summary, qualification):
    lines = [
        '## Problem', '',
        'The retained copied-lease socket regression exposed an ordering conflict: a second owner’s connect-only '
        'liveness probe correctly refused takeover but woke the incumbent’s accept-time pathname check. '
        'The incumbent exited before the fixture restored its original lease pathname.', '',
        '## Changes', '',
        'Remove only the redundant accept-time socket-owner check. The existing bounded complete-frame path still '
        'checks the same lease pathname identity before checkpoint export, lookup, compare-and-advance or a protocol response. '
        'Preserve all three original socket regressions and add a complete-request negative control requiring the precise '
        'pathname fence, nonzero daemon exit, and unchanged socket identity and journal bytes.', '',
        '## Native validation — Draft HOLD', '',
        f'- Tested source: {SOURCE}.', f'- Source tree: {TREE}.',
        f'- Fixed parent evidence: {BASE}, stacked on #{BASE_PR}.',
        f'- Evidence-only sole child: {evidence}.',
        '- Scoped native result: ' + ('PASS' if qualification['native_scope_pass'] else 'FAIL / incomplete') + '.',
        '- Raw originals and ordered part manifest: ' + PREFIX + '/PUBLICATION_PACKAGE.json.', '',
        '| Original command | Exit | Timed out | Outer limit (s) | Elapsed (s) |',
        '| --- | ---: | :---: | ---: | ---: |',
    ]
    for row, (_, _, timeout) in zip(summary['commands'], planned_commands()):
        lines.append(f"| {row['name']} | {row['exit_code']} | {str(row['timed_out']).lower()} | {timeout} | {row['elapsed_ns'] / 1e9:.3f} |")
    lines += ['', 'The complete checkpoint package retained the original 1200-second outer limit, compile profile, '
              'two build jobs, test-thread setting, and internal transport bounds. Its observed libtest blocks are:', '',
              '| Block | Passed | Failed | Ignored | Measured | Filtered | Consistent |',
              '| ---: | ---: | ---: | ---: | ---: | ---: | :---: |']
    for number, block in enumerate(qualification['checkpoint_package']['blocks'], 1):
        counts = block['counts']
        lines.append('| ' + ' | '.join(str(value) for value in (number, counts['passed'], counts['failed'],
                     counts['ignored'], counts['measured'], counts['filtered_out'], block['consistent'])) + ' |')
    if not qualification['checkpoint_package']['blocks']:
        lines.append('| No complete block | — | — | — | — | — | false |')
    lines += ['', 'Observed required socket results:', '']
    for name, values in qualification['checkpoint_package']['socket_tests'].items():
        lines.append('- `' + name + '`: ' + (', '.join(values) if values else 'not completely observed') + '.')
    lines += ['', 'Package parse observations: `' + json.dumps(qualification['checkpoint_package']['parse_errors']) + '`.',
              'The source-integrity controls require exactly 43 successful original cases; observed verdict: `'
              + str(qualification['source_integrity_controls']['complete_success']).lower() + '`.', '',
              '## Preserved prior evidence', '',
              f'The earlier Root source {OLD_SOURCE} and evidence {BASE} retain their original suite timeouts and '
              'socket exit 101. This follow-up did not rerun the Root V3/V4/V5/V6 suites, and none of those results '
              'was relabelled to the new source or evidence child. The prior ignored-log staging refusal and exact '
              'staging-only recovery receipt are retained separately; no old receipt was repaired or hidden.', '',
              'The first socket validation attempt stopped at target admission because its recorded prior build '
              'directory was absent, with zero command records. Its original FAILED.json and traceback remain '
              'under prior-validation-v1. This attempt instead uses a newly created empty private target with '
              'identity checked before and after every command. It does not reconstruct or claim reuse of the '
              'missing target; original command arguments, profile, resources and time limits remain unchanged.', '',
              '## Scope', '',
              'The source delta is limited to two Rust paths, a prepend to the sole development plan, and the three '
              'corresponding existing corpus pins. The archival child adds only manifest-bound evidence and new corpus '
              'pins/required paths. All existing non-corpus source modes and blobs remain equal to the tested source.', '',
              'This remains Draft HOLD. No production merge, deployment or activation is authorized. ARM, an unbuilt '
              'GitHub prospective merge, the original three 30-second campaigns, whole-chain post-quantum qualification, '
              'independent witness custody and actual external provider effects remain outside this scoped result.', '',
              'Exact original command arguments:', '']
    for row in summary['commands']:
        lines += ['- `' + shlex.join(row['command']) + '`.']
    return ('\n'.join(lines) + '\n').encode()


def compare_body(actual, expected):
    if actual == expected:
        return 'exact'
    if expected.endswith(b'\n') and actual == expected[:-1]:
        return 'remote omitted one final LF'
    if actual == expected + b'\n':
        return 'remote added one final LF'
    return None


def pr_detail(number):
    return p.strict_json(p.gh_command('pr', 'view', str(number), '--repo', REPO,
                                    '--json', 'body,title').stdout)


def publish_pr(evidence, summary, qualification, sealed):
    publication_preflight(evidence)
    need(p.remote_head(BRANCH) == evidence, 'remote changed before PR publication')
    p.permitted_delta(SOURCE, evidence, sealed, p.expected_corpus(SOURCE, sealed))
    p.physical_tree(evidence)
    body = pr_body(evidence, summary, qualification)
    title = '[HOLD] Checkpoint socket probe ordering and complete-request fence'
    write(STATE / 'PR_BODY.md', body)
    current = locate_pr()
    previous = None
    if current:
        checked_pr(current, evidence)
        previous = pr_detail(current['number'])
        comparison = compare_body(previous['body'].encode(), body)
        if previous['title'] == title and comparison:
            receipt = {'source': SOURCE, 'evidence': evidence, 'url': current['url'], 'number': current['number'],
                       'draft': True, 'status': 'HOLD', 'submitted_body': identity(body),
                       'observed_body': identity(previous['body'].encode()), 'body_comparison': comparison}
            write_json(STATE / 'PR_RECEIPT.json', receipt)
            return current
    need(not os.path.lexists(STATE / 'PR_CREATE_ATTEMPT.json')
         and not os.path.lexists(STATE / 'PR_EDIT_ATTEMPT.json'),
         'prior PR write response unresolved; exact-branch readback only')
    intent = {'operation_key': PUB_KEY, 'repository': REPO, 'branch': BRANCH, 'base_branch': BASE_BRANCH,
              'base_evidence': BASE, 'source': SOURCE, 'evidence': evidence, 'title': title,
              'body': identity(body), 'actual_payload': 'immutable stdin bytes', 'draft': True}
    if current:
        write_json(STATE / 'PR_BEFORE.json', previous)
        intent.update(number=current['number'], previous_body=identity(previous['body'].encode()))
        write_json(STATE / 'PR_EDIT_ATTEMPT.json', intent)
        need(pr_detail(current['number']) == previous, 'PR body changed after the admitted snapshot')
        argv = ['gh', 'pr', 'edit', str(current['number']), '--repo', REPO, '--title', title, '--body-file', '-']
    else:
        write_json(STATE / 'PR_CREATE_ATTEMPT.json', intent)
        argv = ['gh', 'pr', 'create', '--repo', REPO, '--head', BRANCH, '--base', BASE_BRANCH,
                '--draft', '--title', title, '--body-file', '-']
    no_hold()
    need(p.remote_head(BRANCH) == evidence and p.remote_head(BASE_BRANCH) == BASE, 'remote changed after PR intent')
    try:
        result = p.command(argv, env=p.clean_env(), timeout=180, check=False, stdin=body)
        write_json(STATE / 'PR_COMMAND.json', {'exit_code': result.returncode,
                   'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
    except subprocess.TimeoutExpired:
        write_json(STATE / 'PR_COMMAND.json', {'response': 'UNKNOWN', 'no_success_inferred': True})
    current = locate_pr()
    need(current is not None, 'PR outcome unresolved; no second creation')
    checked_pr(current, evidence)
    actual = pr_detail(current['number'])
    comparison = compare_body(actual['body'].encode(), body)
    need(actual['title'] == title and comparison is not None, 'PR payload not independently reconciled')
    write_json(STATE / 'PR_RECEIPT.json', {'source': SOURCE, 'evidence': evidence, 'url': current['url'],
               'number': current['number'], 'draft': True, 'status': 'HOLD', 'submitted_body': identity(body),
               'observed_body': identity(actual['body'].encode()), 'body_comparison': comparison})
    return current


def own_program():
    argv = getattr(sys, 'orig_argv', [])
    if '-c' in argv:
        return argv[argv.index('-c') + 1].encode()
    return p.read_small(Path(__file__).absolute())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    need(args.publish, 'prepared review artifact; explicit reviewed publication invocation required')
    fully_bound()
    os.umask(0o077)
    sys.dont_write_bytecode = True
    helper_raw = import_helpers()
    clean = p.clean_env()
    os.environ.clear()
    os.environ.update(clean)
    finished_raw = wait_finished()
    checked_source_delta()
    p.repository_identity()
    p.ensure_dirs(STATE)
    write(STATE / 'publisher.lock', b'')
    directory, name, before, stream = p.open_regular(STATE / 'publisher.lock')
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        stream.close()
        os.close(directory)
        raise RuntimeError('another process owns this immutable publication identity')
    globals()['_publisher_lock'] = (directory, stream)
    program = own_program()
    binding = publication_binding(finished_raw, program)
    current = p.gtext('rev-parse', 'HEAD')
    sealed_exists = os.path.lexists(STATE / 'SEALED.json')
    if current == SOURCE and not sealed_exists:
        p.physical_tree(SOURCE)
    else:
        need(sealed_exists, 'unexpected evidence child without sealed intent')
        previous_seal = p.checked_sealed(binding)
        previous_corpus = p.expected_corpus(SOURCE, previous_seal)
        if current == SOURCE:
            worktree_archive(previous_seal, previous_corpus)
        else:
            p.permitted_delta(SOURCE, current, previous_seal, previous_corpus)
            p.physical_tree(current)
    finished, summary, environment, provider, qualification, candidates = validate_native(finished_raw)
    selected = p.clean_env(environment)
    os.environ.clear()
    os.environ.update(selected)
    publication_preflight(current)
    if current == SOURCE and not sealed_exists:
        p.repo_verify(SOURCE)
        p.command(['bash', 'scripts/project-preflight.sh'], env=selected)
    sealed = seal(binding, finished_raw, summary, qualification, candidates, program, helper_raw)
    evidence = archive_commit(sealed, selected)
    final_checks(evidence, selected, sealed)
    p.provider_unchanged(provider)
    no_hold()
    need(p.read_small(OUT / 'VALIDATION_FINISHED.json') == finished_raw, 'native terminal marker changed')
    push(evidence, selected, sealed)
    pr = publish_pr(evidence, summary, qualification, sealed)
    receipt = {'operation_key': PUB_KEY, 'native_source': SOURCE, 'native_tree': TREE,
               'parent_evidence': BASE, 'parent_pr': BASE_PR, 'evidence_commit': evidence,
               'pr': pr['url'], 'draft': True, 'status': 'HOLD', 'publication_complete': True,
               'native_all_commands_passed': summary['all_commands_passed'],
               'native_scope_pass': qualification['native_scope_pass'],
               'root_s879_results_relabelled': False, 'production_activation': False,
               'tests_relabelled_to_evidence_commit': False}
    write_json(STATE / 'PUBLICATION_RECEIPT.json', receipt)
    print(json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Preserve failed/unknown work. No cleanup, source repair, repeated send or new identity.
        if p is not None:
            try:
                write_json(STATE / ('refusal-' + str(time.time_ns()) + '.json'),
                           {'operation_key': PUB_KEY, 'publication_complete': False, 'status': 'REFUSE_OR_UNKNOWN',
                            'error_type': type(error).__name__, 'reason': str(error), 'no_success_inferred': True})
            except Exception:
                pass
        raise
