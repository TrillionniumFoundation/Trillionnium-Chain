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

ROOT = Path('/data/chain-checkpoint-probe-format-20261112-df05')
CONTROL = Path('/data/chain-checkpoint-probe-format-source-20261112-df05')
OUT = Path('/data/chain-checkpoint-probe-format-validation-20261112-df05')
STATE = Path('/data/chain-checkpoint-probe-format-publication-20261112-df05')
PREFIX = 'evidence/checkpoint-socket-probe-format-20261112-df05'
BRANCH = 'fix/chain-checkpoint-probe-20261112-df05'
LOCAL_BRANCH = 'fix/chain-checkpoint-probe-format-20261112-df05'
SOURCE_PARENT = 'b62cb86d22405dd9e5b441970639b6e5dd44a8b8'
SOURCE_PARENT_TREE = '5608b314520cf25068aff5627043d6f8cedd4a41'
PARENT_PR = 947
ROOT_SOURCE = '87943f6229d8785c3f431ede5eadba62b634ab8c'
PR_BASE_BRANCH = 'fix/chain-root-operation-owned-20261112-df05-v4'
PR_BASE = '09e4801308366fac01e55bcbdcf8bdfd4e6d2810'
PR_BASE_TREE = 'f322d45faaa204b641ed2565feca662ef096b161'
PR_BASE_PR = 945
OLD_SOURCE = '7d4303f1a9ba3c259b92e58b85126eef3c5378a1'
OLD_TREE = '2a580a0444f56c0e70e0d73a7fad1120367d1e9e'
OLD_PREFIX = 'evidence/checkpoint-socket-probe-20261112-df05'
PREP_KEY = 'chain-checkpoint-probe-format-source-prep-20261112-df05-v1'
RUN_KEY = 'chain-checkpoint-probe-format-native-validation-20261112-df05-v1'
PUB_KEY = 'chain-checkpoint-probe-format-native-publication-20261112-df05-v1'
REPO = 'TrillionniumFoundation/Trillionnium-Chain'
ORIGIN = 'https://github.com/' + REPO + '.git'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
HELPER = Path('/data/chain-root-publication-bootstrap-20261112-df05-v2/root-native-publisher-v2-df05.py')
HELPER_SHA = '6b42ffccdd9ff216d1ec786813ba3059e0c89550ffbc8c6af6304f415884c40c'
HELPER_BYTES = 89391
VERIFIER_SHA = '0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946'
OWNER_SHA = '389154c792fd3c734621278fb4188e9863ff599efb0c9b863316f540a94eab4a'
SOURCE = '00b3a848009460e425d58b62f9edc9abe9603b78'
TREE = 'e3428012a36210087f5a260f2cf1720d0086fa9e'
DRIVER_SHA = '8c158e2396381c1e5cbab41ec57111356cde131300fc71ff3f9f874f13114126'
DRIVER_INPUT_SHA = 'e9d158514078680ccba9886206adedde1e4c4f396af01f8de876b9b281c7bdfd'
SOURCE_PREP_SHA = 'bd22ede3f6aa7c23321704be8cbf4277b1584972e74bfe6bf8a579ba7373d4db'
PREPARATION = {'frozen_bytes': 3921, 'frozen_sha256': '60aa3769646fa9fc62d8e76b146ab6de8cc846af2ebd90bd2059cdb18b33e697',
    'input_sha256': '2ca425e388c7058b85921f2211fe0c0f9bec58e5f98cb0ee93471d6668a9c0f2',
    'safe_manifest_sha256': 'a583f94a298641c3a55838fdd267279079ba14fead09298464fe85b80d434402'}
PARENT_PUBLICATION_RECEIPT = {'bytes': 700, 'sha256': '6e7fd34fe5da34b4281864888ac01ce5c2a490990ae66d7026f6e4cc142e5b63'}

CAP = 4 * 1024 * 1024
TARGET = Path('/data/chain-checkpoint-probe-target-20261112-df05-v2')
PRIOR_VALIDATION_OUT = Path('/data/chain-checkpoint-probe-validation-20261112-df05-v2')
PRIOR_PUBLICATION_STATE = Path('/data/chain-checkpoint-probe-publication-20261112-df05-v2')

# Expected canonical bytes from the original fixed driver/input. They are not
# claimed as an observed original until safe_history reads the native file.


TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
PROVIDER = Path('/home/qian-qi/credit-envelope-f7e62-provider2/runner/trnm-pq-provider-3.5.9.5yXdk2mN/install')
PROVIDER_HASHES = {
    'bin/openssl': '41d5b79f937beed7f94d9623be504db72c5048fcd952965fc0e13305d2802a33',
    'include/openssl/opensslv.h': '9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda',
    'include/openssl/configuration.h': '406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996',
    'lib/libcrypto.a': '005a0f7d9f6a073e6530cc556c90b3c415df7c6bc2475e333d29aa9bfa409bfb',
    'lib/libssl.a': 'f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727',
}
POST_SHA = {'trillionnium/crates/trnm-checkpoint-store/tests/socket_ownership.rs':
    'cec8a3f76316a75dca33a064d3a41accfbdd4d360359abdc2abf1e4b8f7a0525'}
PLAN_ENTRY_SHA = 'eecce8e6a3d4bb3283c0544b0a0070ec9c9bffe7c9f820ac0b131fc7b81811be'
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
    'prior-validation-finished.json', 'prior-summary.json',
}
SAFE_PREP = {'driver.py', 'THREE_PATH_DELTA.json', 'BASE_PHYSICAL.json', 'COMMITTED_PHYSICAL.json',
             'VERIFIED_PHYSICAL_SOURCE.json', 'STORAGE_ADMISSION.json', 'SHARED_CONFIG_IDENTITY.json'}
SAFE_PREP |= {'PREFLIGHT_' + label + suffix for label in ('BEFORE_EDIT', 'STAGED', 'COMMITTED')
              for suffix in ('.receipt.json', '.stdout', '.stderr')}
PARENT_PR_BODY = {'bytes': 6277, 'sha256': '62b0470dfe44ff2a853243a8bd98e218658d09edf77f8c252d5d3c00b5e9b8c2'}
PARENT_PR_RECEIPT = {'bytes': 536, 'sha256': 'f0ffb3efa9f05342618fd4dc3cee845b3dfd6050e8fe44669ee80aab1bb7f43e'}
EXPECTED_TARGET_IDENTITY = {'device': 2067, 'inode': 26345745, 'mode': 0o700, 'uid': 1000, 'gid': 1000}
LIBRARY_PATH = 'trillionnium/crates/trnm-checkpoint-store/src/lib.rs'
LIBRARY_SHA = '8ad6d9b14300c2df5d674604e4a0107e242c40d6a1e0f1a56d83763015b6f880'
PREVIOUS_TEST_SHA = '6c0482cab4ce234e32ebd388a856f1754aeaa48f299b1996f721420b0bac088f'
PREVIOUS_FORMAT_LOG = {'bytes': 494, 'sha256': 'd80865e3239c62e3bff4d9f8133ea29bbe35ca8972c049d8ba787ba8a8502f51'}
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
    p = types.ModuleType('checkpoint_format_publisher_helpers')
    p.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), p.__dict__)
    for key, value in {'ROOT': ROOT, 'OUT': OUT, 'STATE': STATE, 'PREFIX': PREFIX,
                       'BRANCH': LOCAL_BRANCH, 'BASE_BRANCH': PR_BASE_BRANCH, 'BASE': PR_BASE,
                       'SOURCE': SOURCE, 'TREE': TREE, 'PUB_KEY': PUB_KEY}.items():
        setattr(p, key, value)
    return raw


def fully_bound():
    for name, value, length in (
        ('source', SOURCE, 40), ('tree', TREE, 40), ('source parent', SOURCE_PARENT, 40),
        ('source parent tree', SOURCE_PARENT_TREE, 40), ('PR base', PR_BASE, 40),
        ('PR base tree', PR_BASE_TREE, 40), ('driver', DRIVER_SHA, 64),
        ('driver input', DRIVER_INPUT_SHA, 64), ('source preparation', SOURCE_PREP_SHA, 64),
    ):
        need(re.fullmatch('[0-9a-f]{' + str(length) + '}', value), name + ' is UNBOUND')
    need(SOURCE_PARENT != PR_BASE and LOCAL_BRANCH != BRANCH and PARENT_PR == 947 and PR_BASE_PR == 945,
         'source parent, PR base or local/remote branch identities were conflated')
    need(type(PREPARATION['frozen_bytes']) is int and PREPARATION['frozen_bytes'] > 0
         and all(re.fullmatch('[0-9a-f]{64}', PREPARATION[key])
                 for key in ('frozen_sha256', 'input_sha256', 'safe_manifest_sha256')),
         'preparation remains UNBOUND')
    need(set(PARENT_PUBLICATION_RECEIPT) == {'bytes', 'sha256'}
         and PARENT_PUBLICATION_RECEIPT['bytes'] == 700
         and re.fullmatch('[0-9a-f]{64}', PARENT_PUBLICATION_RECEIPT['sha256']),
         'parent publication receipt remains UNBOUND')
    for value in (PARENT_PR_BODY, PARENT_PR_RECEIPT):
        need(set(value) == {'bytes', 'sha256'} and type(value['bytes']) is int and 0 < value['bytes'] <= CAP
             and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'original parent PR bytes remain UNBOUND')


def write(path, raw):
    p.create_exact(path, raw)
    # Seal every newly-created directory entry as well as the file and leaf directory.
    for parent in (path.parent, *path.parent.parents):
        p.fsync_directory(parent)


def write_json(path, value):
    write(path, p.canonical(value))


def no_hold():
    retained = (Path('/data/chain-checkpoint-probe-20261112-df05'),
                Path('/data/chain-checkpoint-probe-source-20261112-df05'),
                Path('/data/chain-checkpoint-probe-validation-20261112-df05'),
                Path('/data/chain-checkpoint-probe-publication-20261112-df05'))
    for directory in (ROOT, CONTROL, OUT, STATE, PRIOR_VALIDATION_OUT, PRIOR_PUBLICATION_STATE, *retained):
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
         and p.gtext('show', '-s', '--format=%P', SOURCE) == SOURCE_PARENT
         and p.gtext('rev-parse', SOURCE_PARENT + '^{tree}') == SOURCE_PARENT_TREE
         and p.gtext('show', '-s', '--format=%P', SOURCE_PARENT) == OLD_SOURCE
         and p.gtext('rev-parse', OLD_SOURCE + '^{tree}') == OLD_TREE
         and p.gtext('show', '-s', '--format=%P', OLD_SOURCE) == PR_BASE
         and p.gtext('rev-parse', PR_BASE + '^{tree}') == PR_BASE_TREE,
         'source parent differs from the prior socket evidence or fixed Root PR base')
    before, after = p.entries(SOURCE_PARENT), p.entries(SOURCE)
    need(set(before) == set(after), 'source adds/deletes unreviewed paths')
    changed = {name for name in before if before[name] != after[name]}
    need(changed == {*POST_SHA, PLAN, CORPUS}, 'formatter source delta is not three reviewed paths')
    for name in changed:
        need(before[name][0] == after[name][0] == '100644', 'source mode differs')
    for name, expected in POST_SHA.items():
        previous, current = p.git_blob(SOURCE_PARENT, name), p.git_blob(SOURCE, name)
        need(sha(previous) == PREVIOUS_TEST_SHA and sha(current) == expected,
             'formatter preimage or postimage differs')
        need(re.sub(rb'\s+', b'', previous) == re.sub(rb'\s+', b'', current),
             'formatter candidate changes non-whitespace bytes')
    need(before[LIBRARY_PATH] == after[LIBRARY_PATH]
         and sha(p.git_blob(SOURCE, LIBRARY_PATH)) == LIBRARY_SHA,
         'previous socket production fix changed during formatter follow-up')
    old_plan, new_plan = p.git_blob(SOURCE_PARENT, PLAN), p.git_blob(SOURCE, PLAN)
    need(new_plan.endswith(old_plan) and len(new_plan) > len(old_plan), 'sole plan suffix changed')
    prepend = new_plan[:-len(old_plan)]
    need(prepend.endswith(b'\n\n') and sha(prepend[:-1]) == PLAN_ENTRY_SHA, 'plan prepend changed')
    original = p.strict_json(p.git_blob(SOURCE_PARENT, CORPUS))
    expected = copy.deepcopy(original)
    for name in (*POST_SHA, PLAN):
        need(name in original['required_paths'] and original['pinned_blobs'][name] == before[name][1],
             'original source corpus pin differs')
        expected['pinned_blobs'][name] = after[name][1]
    need(p.strict_json(p.git_blob(SOURCE, CORPUS)) == expected, 'source corpus changed outside two existing pins')
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
    need(frozen['schema'] == 'checkpoint-probe-format-source-v1' and frozen['operation_key'] == PREP_KEY
         and frozen['head'] == SOURCE and frozen['tree'] == TREE and frozen['parent'] == SOURCE_PARENT
         and frozen['parent_tree'] == SOURCE_PARENT_TREE and frozen['worktree'] == str(ROOT)
         and frozen['branch'] == LOCAL_BRANCH and frozen['program_sha256'] == SOURCE_PREP_SHA,
         'source preparation identity mismatch')
    need(frozen['input_sha256'] == PREPARATION['input_sha256']
         and frozen['safe_manifest_sha256'] == PREPARATION['safe_manifest_sha256'], 'preparation input/manifest pin changed')
    for name in ('unchanged_outside_three_paths', 'source_clean', 'shared_config_unchanged', 'old_source_head_unchanged'):
        need(frozen[name] is True, 'source preparation integrity not established')
    for name in ('old_failures_reused_as_new_pass', 'native_tests_executed', 'publication_performed', 'production_activation'):
        need(frozen[name] is False, 'source preparation overclaims')
    need(frozen['status'] == 'HOLD' and frozen['prior_socket_source'] == OLD_SOURCE
         and frozen['allowed_corpus_pin_paths'] == [*POST_SHA, PLAN], 'source preparation scope differs')
    need(frozen['remote_branch'] == BRANCH and frozen['pr_base_evidence'] == PR_BASE
         and frozen['pr_base_branch'] == PR_BASE_BRANCH and frozen['pr_base_pr'] == PR_BASE_PR,
         'preparation local/source-parent and remote/PR-base identities were conflated')
    parent = frozen['parent_pr']
    need(parent['number'] == PARENT_PR and parent['headRefOid'] == SOURCE_PARENT
         and parent['headRefName'] == BRANCH and parent['baseRefName'] == PR_BASE_BRANCH
         and parent['url'] == 'https://github.com/' + REPO + '/pull/' + str(PARENT_PR)
         and parent['author_login'] == 'ProfHepta' and parent['state'] == 'OPEN' and parent['isDraft'] is True,
         'preparation previous socket Draft differs')
    need(frozen['parent_publication_receipt'] == PARENT_PUBLICATION_RECEIPT
         and frozen['parent_publication_terminal_projection'] == {
             'job_id': '1a1cff1cde7-2564-1af1',
             'operation_key': 'chain-checkpoint-probe-native-publication-20261112-df05-v2',
             'state': 'succeeded', 'exit_code': 0, 'timed_out': False,
             'output_complete': True, 'output_durable': True, 'terminal_publication_confirmed': True},
         'preparation previous publisher closure differs')
    safe_raw = p.read_small(CONTROL / 'SAFE_MANIFEST.json', scan=True)
    need(sha(safe_raw) == frozen['safe_manifest_sha256'], 'safe source-preparation manifest changed')
    safe = p.strict_json(safe_raw)
    need(safe['schema'] == 'checkpoint-probe-format-source-safe-manifest-v1' and safe['source'] == SOURCE
         and safe['tree'] == TREE and safe['parent_evidence'] == SOURCE_PARENT, 'safe manifest identity differs')
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
    delta = p.strict_json(preparation_bytes['THREE_PATH_DELTA.json'])
    need(delta == frozen['three_path_delta'] and len(delta) == 3, 'preparation delta differs')
    before, after = p.entries(SOURCE_PARENT), p.entries(SOURCE)
    need({row['path'] for row in delta} == {*POST_SHA, PLAN, CORPUS}, 'preparation delta paths differ')
    for row in delta:
        name = row['path']
        need((row['old_mode'], row['old_blob'], row['old_bytes']) == before[name]
             and (row['new_mode'], row['new_blob'], row['new_bytes']) == after[name]
             and row['old_sha256'] == sha(p.git_blob(SOURCE_PARENT, name))
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
         and closure['schema'] == 'checkpoint-probe-format-prior-owner-closure-v1',
         'prior owner projection differs')
    for name, job, key in (
        ('validation', '1a1cfe86859-2564-1ae2', 'chain-checkpoint-probe-native-validation-20261112-df05-v2'),
        ('publication', '1a1cff1cde7-2564-1af1', 'chain-checkpoint-probe-native-publication-20261112-df05-v2'),
    ):
        need(closure[name] == {'job_id': job, 'operation_key': key, 'runtime_idempotency_key': key,
             'state': 'succeeded', 'exit_code': 0, 'timed_out': False,
             'output_complete': True, 'output_durable': True, 'terminal_publication_confirmed': True},
             'prior native owner terminal remains unconfirmed')
        need(type(closure[name]['exit_code']) is int and closure[name]['timed_out'] is False
             and all(closure[name][field] is True
                     for field in ('output_complete', 'output_durable', 'terminal_publication_confirmed')),
             'prior native owner terminal types differ')
    prior_raw = read_bound('prior-publication-receipt.json')
    need(closure['publication_receipt'] == PARENT_PUBLICATION_RECEIPT == identity(prior_raw),
         'prior publication receipt identity differs')
    expected_receipt = {'operation_key': 'chain-checkpoint-probe-native-publication-20261112-df05-v2',
        'native_source': OLD_SOURCE, 'native_tree': OLD_TREE, 'parent_evidence': PR_BASE,
        'parent_pr': PR_BASE_PR, 'evidence_commit': SOURCE_PARENT,
        'pr': 'https://github.com/' + REPO + '/pull/' + str(PARENT_PR),
        'draft': True, 'publication_complete': True, 'native_all_commands_passed': False,
        'native_scope_pass': False, 'status': 'HOLD', 'production_activation': False,
        'root_s879_results_relabelled': False, 'tests_relabelled_to_evidence_commit': False}
    need(p.strict_json(prior_raw) == expected_receipt and prior_raw == p.canonical(expected_receipt),
         'prior qualification was relabelled')
    retained = {}
    for name, archived in (
        ('prior-environment.json', 'native/environment.json'),
        ('prior-validation-finished.json', 'native/VALIDATION_FINISHED.json'),
        ('prior-summary.json', 'native/SUMMARY.json'),
    ):
        raw = read_bound(name)
        need(raw == p.git_blob(SOURCE_PARENT, OLD_PREFIX + '/' + archived),
             'prior receipt is not its exact socket evidence original')
        retained[name] = p.strict_json(raw)
    old_env = retained['prior-environment.json']
    need(old_env['source'] == OLD_SOURCE and old_env['tree'] == OLD_TREE
         and old_env['target_identity'] == EXPECTED_TARGET_IDENTITY
         and old_env['target_identity_rechecked_per_command'] is True,
         'prior environment or actual target differs')
    selected = selected_environment()
    need(set(old_env['environment']) == set(selected) and all(
         old_env['environment'][name] == value for name, value in selected.items()
         if name not in ('TMPDIR', 'PYTHONPYCACHEPREFIX')),
         'native profile/resources/target changed beyond new temporary paths')
    old_finished = retained['prior-validation-finished.json']
    old_summary = retained['prior-summary.json']
    need(old_finished['source'] == OLD_SOURCE and old_finished['tree'] == OLD_TREE
         and old_finished['all_commands_passed'] is False
         and old_finished['summary_sha256'] == sha(read_bound('prior-summary.json'))
         and old_finished['manifest_sha256'] == sha(p.git_blob(SOURCE_PARENT, OLD_PREFIX + '/native/ARTIFACT_MANIFEST.json')),
         'prior FINISHED no longer binds the original failed-format run')
    need(old_summary['source'] == OLD_SOURCE and old_summary['tree'] == OLD_TREE
         and old_summary['source_consistent'] is True and old_summary['target_identity_consistent'] is True
         and old_summary['all_commands_passed'] is False and len(old_summary['commands']) == 14,
         'prior complete fourteen-command scope differs')
    need(old_summary['commands'] == p.strict_json(p.git_blob(SOURCE_PARENT, OLD_PREFIX + '/native/commands.json')),
         'prior summary command receipts differ')
    for row, (name, argv, _) in zip(old_summary['commands'], planned_commands()):
        need(row['name'] == name and row['command'] == argv and row['source'] == OLD_SOURCE
             and row['expected_source'] == OLD_SOURCE and row['executed'] is True
             and all(row[key] is True for key in ('source_verified', 'source_before_verified', 'source_after_verified'))
             and row['exit_code'] == (1 if name == 'format' else 0) and row['timed_out'] is False
             and row['target_before_identity'] == EXPECTED_TARGET_IDENTITY == row['target_after_identity']
             and row['target_identity_error'] is None,
             'prior formatting failure or source/target observations were relabelled')
    need(identity(p.git_blob(SOURCE_PARENT, OLD_PREFIX + '/native/format.log')) == PREVIOUS_FORMAT_LOG,
         'original formatter failure log changed')


def validate_reused_target_admission(env_document, target_id):
    admission = env_document['target_admission']
    need(target_id == EXPECTED_TARGET_IDENTITY and admission['path'] == str(TARGET)
         and admission['identity'] == target_id == admission['expected_prior_identity']
         and admission['prior_source'] == OLD_SOURCE and admission['prior_environment_target'] == str(TARGET),
         'retained target differs from the observed closed prior incarnation')
    need(admission['reused_after_verified_prior_owners_closed'] is True
         and all(admission[name] is False for name in ('new_target_created', 'target_recreated', 'fallback_permitted')),
         'target admission permits an unreviewed creation, repair or fallback')
    need(env_document['minimum_free_bytes_before_command'] == 10 * 1024 ** 3
         and type(env_document['before_target_disk']['free']) is int
         and env_document['before_target_disk']['free'] >= 10 * 1024 ** 3
         and type(env_document['before_output_disk']['free']) is int
         and env_document['before_output_disk']['free'] >= 1024 ** 3,
         'original native disk reserve admission changed')








def validate_native(finished_raw):
    no_hold()
    finished = p.strict_json(finished_raw)
    need(set(finished) == {'schema', 'operation_key', 'source', 'tree', 'parent_evidence',
                          'manifest_sha256', 'summary_sha256', 'all_commands_passed', 'status', 'publication_performed'},
         'FINISHED fields differ')
    need(finished['schema'] == 'checkpoint-probe-format-native-finished-v1' and finished['operation_key'] == RUN_KEY
         and finished['source'] == SOURCE and finished['tree'] == TREE and finished['parent_evidence'] == SOURCE_PARENT
         and finished['status'] == 'HOLD' and finished['publication_performed'] is False, 'FINISHED identity or scope differs')
    manifest_raw = p.read_small(OUT / 'ARTIFACT_MANIFEST.json', scan=True)
    summary_raw = p.read_small(OUT / 'SUMMARY.json', scan=True)
    need(sha(manifest_raw) == finished['manifest_sha256'] and sha(summary_raw) == finished['summary_sha256'],
         'FINISHED does not bind exact native metadata')
    manifest, summary = p.strict_json(manifest_raw), p.strict_json(summary_raw)
    need(set(manifest) == {'source', 'tree', 'parent_evidence', 'artifacts'} and manifest['source'] == SOURCE
         and manifest['tree'] == TREE and manifest['parent_evidence'] == SOURCE_PARENT, 'manifest schema/source differs')
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
         and invocation['parent_evidence'] == SOURCE_PARENT and invocation['parent_tree'] == SOURCE_PARENT_TREE
         and invocation['driver_sha256'] == DRIVER_SHA and invocation['input_sha256'] == DRIVER_INPUT_SHA,
         'native invocation differs from reviewed input')
    frozen, preparation_files = validate_preparation(read_bound('source-preparation.json'))
    checked_prior(read_bound)
    env_document = p.strict_json(read_bound('environment.json'))
    selected = selected_environment()
    need(env_document['source'] == SOURCE and env_document['tree'] == TREE and env_document['parent_evidence'] == SOURCE_PARENT
         and env_document['environment'] == selected and env_document['optimization_or_debug_profile_overrides'] is False
         and env_document['isolated_new_target'] is False
         and env_document['reused_target_after_verified_prior_owner_terminal'] is True,
         'native environment was substituted')
    target_id = env_document['target_identity']
    need(set(target_id) == {'device', 'inode', 'mode', 'uid', 'gid'}
         and all(type(value) is int and value >= 0 for value in target_id.values())
         and target_id['inode'] > 0 and target_id['mode'] == 0o700 and target_id['uid'] == os.geteuid()
         and env_document['target_identity_rechecked_per_command'] is True,
         'native target identity not bound')
    validate_reused_target_admission(env_document, target_id)
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
    need(actual_plan['source'] == SOURCE and actual_plan['tree'] == TREE and actual_plan['parent_evidence'] == SOURCE_PARENT
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
    need(summary['schema'] == 'checkpoint-probe-format-native-validation-v1' and summary['operation_key'] == RUN_KEY
         and summary['source'] == SOURCE and summary['tree'] == TREE and summary['parent_evidence'] == SOURCE_PARENT
         and summary['parent_tree'] == SOURCE_PARENT_TREE and summary['source_consistent'] is True
         and summary['provider_unchanged'] is True and summary['target_identity_consistent'] is True
         and summary['status'] == 'HOLD', 'native summary identity/integrity differs')
    need(summary['all_commands_passed'] is passed and finished['all_commands_passed'] is passed
         and all(summary[name] is False for name in ('root_s879_native_qualification_reused', 'prior_socket_results_reused_as_new_pass', 'production_activation', 'publication_performed')),
         'native summary overclaims')
    by_name = {row['name']: row for row in rows}
    package = observe_bound_file('checkpoint-package.log', artifacts['checkpoint-package.log'],
                                 observe_package, by_name['checkpoint-package']['exit_code'])
    controls = observe_bound_file('source-integrity-controls.log', artifacts['source-integrity-controls.log'],
                                  observe_source_controls, by_name['source-integrity-controls']['exit_code'])
    qualification = {'all_original_commands_passed': passed, 'checkpoint_package': package,
                     'source_integrity_controls': controls,
                     'native_scope_pass': passed and package['complete_success'] and controls['complete_success'],
                     'old_root_s879_results_relabelled': False, 'old_socket_results_relabelled': False, 'whole_chain_pq_qualified': False,
                     'arm_verified': False, 'prospective_merge_verified': False,
                     'original_three_30s_campaigns_verified': False, 'production_activation': False,
                     'status': 'HOLD'}
    candidates = [(OUT / name, 'native/' + name, item) for name, item in sorted(artifacts.items())]
    candidates += [(OUT / 'ARTIFACT_MANIFEST.json', 'native/ARTIFACT_MANIFEST.json', identity(manifest_raw)),
                   (OUT / 'VALIDATION_FINISHED.json', 'native/VALIDATION_FINISHED.json', identity(finished_raw))]
    need(p.read_small(OUT / 'VALIDATION_FINISHED.json') == finished_raw, 'FINISHED changed during validation')
    return finished, summary, selected, provider, qualification, candidates + preparation_files


def previous_pr_originals():
    body = p.read_small(PRIOR_PUBLICATION_STATE / 'PR_BODY.md', scan=True)
    raw = p.read_small(PRIOR_PUBLICATION_STATE / 'PR_RECEIPT.json', scan=True)
    need(identity(body) == PARENT_PR_BODY and identity(raw) == PARENT_PR_RECEIPT,
         'original parent PR body or publication receipt bytes changed')
    receipt = p.strict_json(raw)
    need(receipt['source'] == OLD_SOURCE and receipt['evidence'] == SOURCE_PARENT
         and receipt['number'] == PARENT_PR and receipt['url'] == 'https://github.com/' + REPO + '/pull/' + str(PARENT_PR)
         and receipt['draft'] is True and receipt['status'] == 'HOLD'
         and receipt['submitted_body'] == identity(body), 'parent PR receipt scope differs')
    allowed = [body, body + b'\n'] + ([body[:-1]] if body.endswith(b'\n') else [])
    need(any(receipt['observed_body'] == identity(value)
             and receipt['body_comparison'] == compare_body(value, body) for value in allowed),
         'parent PR receipt changed its narrow actual-body comparison')
    return body, raw


def safe_history():
    # The entire previous evidence tree, including the original format failure,
    # admission failure, staging refusal and recovery, remains byte-identical in
    # SOURCE_PARENT and is inherited by SOURCE. New prior-owner snapshots are
    # already manifest-bound native artifacts. Preserve the actual old submitted
    # PR body and its receipt explicitly, without a private SDK/index/input walk.
    previous_pr_originals()
    return [(PRIOR_PUBLICATION_STATE / 'PR_BODY.md', 'prior-publication/PR_BODY.md', PARENT_PR_BODY),
            (PRIOR_PUBLICATION_STATE / 'PR_RECEIPT.json', 'prior-publication/PR_RECEIPT.json', PARENT_PR_RECEIPT)]


def publication_binding(finished_raw, program):
    finished = p.strict_json(finished_raw)
    return {'schema': 'checkpoint-probe-format-publication-intent-v1', 'operation_key': PUB_KEY,
            'source': SOURCE, 'source_tree': TREE, 'parent_evidence': SOURCE_PARENT,
            'parent_tree': SOURCE_PARENT_TREE, 'parent_pr': PARENT_PR,
            'pr_base_evidence': PR_BASE, 'pr_base_tree': PR_BASE_TREE,
            'pr_base_pr': PR_BASE_PR, 'pr_base_branch': PR_BASE_BRANCH,
            'local_branch': LOCAL_BRANCH, 'remote_branch': BRANCH, 'repository': REPO,
            'validation_operation_key': RUN_KEY, 'validation_directory': str(OUT),
            'validation_driver_sha256': DRIVER_SHA, 'validation_input_sha256': DRIVER_INPUT_SHA,
            'native_manifest_sha256': finished['manifest_sha256'], 'native_summary_sha256': finished['summary_sha256'],
            'native_finished_sha256': sha(finished_raw), 'publisher_sha256': sha(program),
            'helper_sha256': HELPER_SHA, 'source_preparation_program_sha256': SOURCE_PREP_SHA,
            'source_preparation': PREPARATION, 'parent_publication_receipt': PARENT_PUBLICATION_RECEIPT,
            'parent_pr_body': PARENT_PR_BODY, 'parent_pr_receipt': PARENT_PR_RECEIPT,
            'retained_target': str(TARGET), 'retained_target_identity': EXPECTED_TARGET_IDENTITY,
            'prior_target_reused_after_owners_closed': True, 'target_creation_or_fallback_permitted': False}


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
            'schema': 'checkpoint-probe-format-publication-package-v1', 'binding': binding,
            'native_commands': summary['commands'], 'qualification': qualification, 'originals': originals,
            'chunk_byte_cap': CAP, 'raw_original_bytes_preserved': True,
            'prior_runtime_closure_basis': 'controller-pinned authoritative terminal projection; not a claim inferred from GitHub',
            'old_root_source': ROOT_SOURCE, 'previous_socket_source': OLD_SOURCE,
            'previous_socket_tree': OLD_TREE, 'previous_socket_evidence': SOURCE_PARENT,
            'root_s879_suite_results_relabelled': False, 'old_socket_results_relabelled': False,
            'private_sdk_input_or_indexes_included': False,
            'archive_scope': 'fixed manifest-bound native output, sixteen safe preparation files and two exact prior PR originals; complete prior evidence inherited unchanged',
            'prior_format_failure_preserved_in_parent': True,
            'retained_target_reused_after_owners_closed': True, 'target_creation_or_fallback_permitted': False,
            'status': 'HOLD', 'production_activation': False,
        }),
        'README.md': (
            '# Checkpoint socket formatter follow-up — Draft HOLD\n\n'
            f'Tested source: {SOURCE}\n\nSource tree: {TREE}\n\n'
            f'Immediate source parent: {SOURCE_PARENT} (previous socket Draft #{PARENT_PR} evidence).\n\n'
            f'Unchanged PR base: {PR_BASE} (Root Draft #{PR_BASE_PR}).\n\n'
            'This source changes only the formatter layout of the new socket regression assertion, a prepend '
            'to the sole development plan, and their two existing corpus pins. The production socket implementation '
            'and all four test behaviors remain unchanged.\n\n'
            '[Native summary](native/SUMMARY.json), [original command receipts](native/commands.json), '
            '[source qualification](SOURCE_QUALIFICATION.json), [ordered original-byte manifest](PUBLICATION_PACKAGE.json), '
            '[source preparation](source-preparation/FROZEN.json).\n\n'
            'All fourteen original commands are run again on this exact new source. The complete checkpoint package '
            'uses the original 1200-second outer limit, profile, resource limits and test-thread setting. '
            'Every real exit and timeout is retained. The earlier socket source ' + OLD_SOURCE + ' had thirteen '
            'successful commands and format exit 1; its complete logs and evidence remain unchanged in the parent commit. '
            'The Root V3/V4/V5/V6 results remain attached to ' + ROOT_SOURCE + ' and were not rerun here.\n\n'
            'The retained target is admitted by its exact previously observed directory identity after both earlier '
            'native owners have authoritative terminal evidence. Every command rechecks that identity. No target '
            'creation, repair or fallback is allowed by this invocation.\n\n'
            'The evidence commit is a sole archival child of the new tested source. Ordinary fast-forward push '
            'updates the same socket Draft; the new local checkout branch is not the remote PR branch. '
            'Files above the unchanged 4 MiB corpus cap are stored in ordered parts with original lengths and SHA-256. '
            'The actual [previous PR body](prior-publication/PR_BODY.md) and its exact receipt are retained. '
            'Private SDK records, input bodies and Git indexes are excluded.\n\n'
            'This remains Draft HOLD. ARM, prospective GitHub merge validation, the original three 30-second campaigns, '
            'whole-chain post-quantum qualification, independent authority custody, actual external effects and production '
            'activation are outside these observations.\n'
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
    p.git(*INDEX, 'commit', '-m', 'test(checkpoint): retain socket formatter follow-up evidence with HOLD')
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
                       '--base', PR_BASE_BRANCH, '--limit', '100', '--json',
                       'number,url,state,isDraft,headRefName,headRefOid,baseRefName,author').stdout
    rows = p.strict_json(raw)
    need(type(rows) is list and len(rows) <= 1, 'ambiguous exact branch/base PR')
    return rows[0] if rows else None


def checked_pr(pr, evidence):
    need(pr['number'] == PARENT_PR and pr['state'] == 'OPEN' and pr['isDraft'] is True
         and pr['headRefName'] == BRANCH and pr['headRefOid'] == evidence
         and pr['baseRefName'] == PR_BASE_BRANCH and pr['author']['login'] == 'ProfHepta'
         and pr['url'] == 'https://github.com/' + REPO + '/pull/' + str(PARENT_PR),
         'existing socket PR scope/number/actor/state differs')


def publication_preflight(current):
    no_hold()
    p.actor()
    p.repository_identity()  # helper BRANCH is deliberately LOCAL_BRANCH
    headers = p.git('config', '--get-regexp', r'^http\..*extraheader$', check=False)
    need(headers.returncode == 1 and not headers.stdout, 'Git HTTP extraHeader needs explicit reconciliation')
    parent = p.strict_json(p.gh_command('pr', 'view', str(PR_BASE_PR), '--repo', REPO, '--json',
                          'number,state,isDraft,headRefName,headRefOid,author').stdout)
    need(parent['number'] == PR_BASE_PR and parent['state'] == 'OPEN' and parent['isDraft'] is True
         and parent['headRefName'] == PR_BASE_BRANCH and parent['headRefOid'] == PR_BASE
         and parent['author']['login'] == 'ProfHepta', 'fixed Root PR base moved or changed state')
    need(p.remote_head(PR_BASE_BRANCH) == PR_BASE, 'fixed stacked base moved')
    remote = p.remote_head(BRANCH)
    allowed = {SOURCE_PARENT} if current == SOURCE else {SOURCE_PARENT, current}
    need(remote in allowed, 'remote socket branch is not the exact previous or current evidence')
    need(p.git('merge-base', '--is-ancestor', SOURCE_PARENT, SOURCE, check=False).returncode == 0,
         'new source does not descend from previous socket evidence')
    current_pr = locate_pr()
    need(current_pr is not None, 'existing socket Draft disappeared; do not create another PR')
    checked_pr(current_pr, remote)
    snapshot_path = STATE / 'PREVIOUS_PR.json'
    if not os.path.lexists(snapshot_path):
        need(remote == SOURCE_PARENT, 'new remote head has no durable original PR snapshot')
        original_body, _ = previous_pr_originals()
        detail = pr_detail(PARENT_PR)
        need(detail['title'] == '[HOLD] Checkpoint socket probe ordering and complete-request fence'
             and compare_body(detail['body'].encode(), original_body) is not None,
             'current parent PR does not match the actual previously submitted body')
        previous = {'source_parent': SOURCE_PARENT, 'pr_base_evidence': PR_BASE,
                    'pr': current_pr, 'detail': detail}
        write_json(snapshot_path, previous)
    snapshot = p.jread(snapshot_path)
    need(snapshot['source_parent'] == SOURCE_PARENT and snapshot['pr_base_evidence'] == PR_BASE,
         'previous PR snapshot belongs to another publication')
    checked_pr(snapshot['pr'], SOURCE_PARENT)
    need(type(snapshot['detail']['body']) is str and type(snapshot['detail']['title']) is str,
         'previous PR body/title snapshot malformed')
    if remote == SOURCE_PARENT:
        need(pr_detail(PARENT_PR) == snapshot['detail'], 'previous PR body/title changed before push')


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
        '## Problem and change', '',
        'The copied-lease regression exposed an ordering conflict: a second owner’s connect-only liveness probe '
        'correctly refused takeover but woke the incumbent’s redundant accept-time pathname check. The original '
        'socket change removes only that accept-time check. The bounded complete-frame path still checks the '
        'same lease pathname before checkpoint export, lookup, compare-and-advance or any response. All three '
        'original regressions remain, plus a complete-request negative control.', '',
        'The first socket run passed thirteen commands and failed formatting on the final assertion in the new '
        'regression. This follow-up applies exactly that rustfmt layout, adds a sole-plan entry, and updates two '
        'existing corpus pins. The production implementation and all four test behaviors are unchanged.', '',
        '## Native validation — Draft HOLD', '',
        f'- Tested source: {SOURCE}.', f'- Source tree: {TREE}.',
        f'- Immediate source parent: {SOURCE_PARENT}, the previous evidence of this same Draft #{PARENT_PR}.',
        f'- Unchanged PR base: {PR_BASE}, Root Draft #{PR_BASE_PR}.',
        f'- Evidence-only sole child: {evidence}.',
        '- Scoped native result: ' + ('PASS' if qualification['native_scope_pass'] else 'FAIL / incomplete') + '.',
        '- Raw originals and ordered part manifest: ' + PREFIX + '/PUBLICATION_PACKAGE.json.', '',
        '| Original command | Exit | Timed out | Outer limit (s) | Elapsed (s) |',
        '| --- | ---: | :---: | ---: | ---: |',
    ]
    for row, (_, _, timeout) in zip(summary['commands'], planned_commands()):
        lines.append(f"| {row['name']} | {row['exit_code']} | {str(row['timed_out']).lower()} | {timeout} | {row['elapsed_ns'] / 1e9:.3f} |")
    lines += ['', 'All fourteen commands ran again on the new source, with the original profile, two build jobs, '
              '1200-second checkpoint-package limit, single test thread and internal transport bounds.', '',
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
              '## Preserved history and scope', '',
              f'The earlier socket source {OLD_SOURCE} retains its original format exit 1 and all original logs in '
              f'{SOURCE_PARENT}. Its results are not relabelled as results of this new source. The initial target '
              'admission failure, earlier staging refusal and narrow recovery are also inherited unchanged. '
              'The actual previous PR body and its publication receipt are retained under the new archive’s '
              'prior-publication directory. '
              f'The Root suites remain attached to {ROOT_SOURCE}; this follow-up did not rerun Root V3/V4/V5/V6.', '',
              'The exact previously observed build-target directory is reused only after both previous native '
              'owners are authoritatively closed; every command checks the same incarnation. This invocation '
              'does not create, repair or fall back to another target.', '',
              'A new isolated local branch holds this source. The actual pushed payload is the immutable evidence '
              'commit, using a normal fast-forward to the existing socket PR branch. The PR base remains Root #945. '
              'The archival child adds only manifest-bound evidence and new corpus pins/required paths; all '
              'existing non-corpus blobs and modes remain equal to the tested source.', '',
              'This remains Draft HOLD. No merge, deployment or activation is performed. ARM, an unbuilt GitHub '
              'prospective merge, the original three 30-second campaigns, whole-chain post-quantum qualification, '
              'independent witness custody and actual external provider effects remain outside this result.', '',
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
    need(p.remote_head(BRANCH) == evidence, 'remote changed before PR update')
    p.permitted_delta(SOURCE, evidence, sealed, p.expected_corpus(SOURCE, sealed))
    p.physical_tree(evidence)
    body = pr_body(evidence, summary, qualification)
    title = '[HOLD] Checkpoint socket probe ordering and complete-request fence'
    write(STATE / 'PR_BODY.md', body)
    current = locate_pr()
    need(current is not None, 'existing socket Draft missing; creating a replacement is prohibited')
    checked_pr(current, evidence)
    previous = pr_detail(PARENT_PR)
    comparison = compare_body(previous['body'].encode(), body)
    if previous['title'] == title and comparison:
        write_json(STATE / 'PR_RECEIPT.json', {'source': SOURCE, 'evidence': evidence,
                   'url': current['url'], 'number': PARENT_PR, 'draft': True, 'status': 'HOLD',
                   'submitted_body': identity(body), 'observed_body': identity(previous['body'].encode()),
                   'body_comparison': comparison})
        return current
    need(not os.path.lexists(STATE / 'PR_EDIT_ATTEMPT.json'),
         'prior PR write response unresolved; exact-PR readback only')
    original = p.jread(STATE / 'PREVIOUS_PR.json')
    need(previous == original['detail'], 'PR body/title differs from the original admitted snapshot')
    intent = {'operation_key': PUB_KEY, 'repository': REPO, 'local_branch': LOCAL_BRANCH,
              'remote_branch': BRANCH, 'pr_base_branch': PR_BASE_BRANCH, 'pr_base_evidence': PR_BASE,
              'parent_evidence': SOURCE_PARENT, 'source': SOURCE, 'evidence': evidence,
              'number': PARENT_PR, 'title': title, 'body': identity(body),
              'previous_body': identity(previous['body'].encode()),
              'actual_payload': 'immutable stdin bytes', 'draft': True, 'create_new_pr_permitted': False}
    write_json(STATE / 'PR_BEFORE.json', previous)
    write_json(STATE / 'PR_EDIT_ATTEMPT.json', intent)
    need(pr_detail(PARENT_PR) == previous, 'PR body changed after the admitted snapshot')
    no_hold()
    need(p.remote_head(BRANCH) == evidence and p.remote_head(PR_BASE_BRANCH) == PR_BASE,
         'remote changed after PR intent')
    try:
        result = p.command(['gh', 'pr', 'edit', str(PARENT_PR), '--repo', REPO,
                            '--title', title, '--body-file', '-'],
                           env=p.clean_env(), timeout=180, check=False, stdin=body)
        write_json(STATE / 'PR_COMMAND.json', {'exit_code': result.returncode,
                   'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
    except subprocess.TimeoutExpired:
        write_json(STATE / 'PR_COMMAND.json', {'response': 'UNKNOWN', 'no_success_inferred': True})
    current = locate_pr()
    need(current is not None, 'PR update outcome unresolved; no second update or replacement')
    checked_pr(current, evidence)
    actual = pr_detail(PARENT_PR)
    comparison = compare_body(actual['body'].encode(), body)
    need(actual['title'] == title and comparison is not None, 'PR payload not independently reconciled')
    write_json(STATE / 'PR_RECEIPT.json', {'source': SOURCE, 'evidence': evidence, 'url': current['url'],
               'number': PARENT_PR, 'draft': True, 'status': 'HOLD', 'submitted_body': identity(body),
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
               'parent_evidence': SOURCE_PARENT, 'parent_pr': PARENT_PR,
               'pr_base_evidence': PR_BASE, 'pr_base_pr': PR_BASE_PR,
               'local_branch': LOCAL_BRANCH, 'remote_branch': BRANCH, 'evidence_commit': evidence,
               'pr': pr['url'], 'draft': True, 'status': 'HOLD', 'publication_complete': True,
               'native_all_commands_passed': summary['all_commands_passed'],
               'native_scope_pass': qualification['native_scope_pass'],
               'root_s879_results_relabelled': False, 'prior_socket_results_relabelled': False, 'production_activation': False,
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
