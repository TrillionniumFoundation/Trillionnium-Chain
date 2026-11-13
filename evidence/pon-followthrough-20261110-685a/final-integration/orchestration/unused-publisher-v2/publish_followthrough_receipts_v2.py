#!/usr/bin/env python3
"""Retain actual failed-native and complete C3 observations for draft review.

No phase is executed merely by importing this recorder. all-local means prepare,
commit and validate; GitHub writes require --phase publish. A pending remote
write is reconciled read-only on resume and is never blindly submitted again.
"""
from __future__ import annotations

import argparse
import ast
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import time
import uuid

BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
PREFIX = 'evidence/pon-followthrough-20261110-685a/final-integration'
VERIFY = 'scripts/ci/verify_ci_source.py'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
OWNER = 'TrillionniumFoundation'
ACCOUNT = 'ProfHepta'
PR_BASE = 'fix/chain-hepta-closure-candidate-20261109-481716'
TITLE = 'fix(pon): retain readback fixes and failed native observations for draft review'
MARKER = '<!-- pon-followthrough-20261110-685a -->'
COMMIT_MESSAGE = 'docs(pon): retain failed native and complete integration observations'
CONTROLLER_SHA = '1075c69186b95bb8e3423693fbb931f375d5afa93dd6fc023a02715945d9e920'
NATIVE_SHA = '2613c863a3ff1c554196ff04d946738c55e763b1858ec627f4a0f9c35589891e'
DRIVER_SHA = '7583b9e869e79eb9edb02fdb8f9033b9bf0af0e5f7720cba8338cac7b02302e2'
BUNDLE_SHA = '349fc885bee13aa2c12ff18987fe3fdbb5b33136f5567538f301217cc1407bb1'
BUNDLE_MANIFEST = 'integration/controller-input-manifest-v3.json'
CONTROLLER_PATH = 'integration/integrate_candidate_v3.py'
BUNDLE_MEMBERS = 14
V2_IDENTITIES_FROZEN = True  # Pins identify driver-03; actual completion is still required at runtime.
HISTORICAL_DRIVER_SHA = '08226df52b1ca3d5627b123ca034d8f708f5b32bcc0f2b4d29ecbb3ad58b963f'
HISTORICAL_BUNDLE_SHA = '1c3ebf117c31271d118095fd31be34aa6add4f335173f044f325f71526656488'
HISTORICAL_CONTROLLER_SHA = 'a1dab7802752d4f534c3d70f40d6bceca1b5eb156c0d1229dfa9306e29c74c62'
HISTORICAL_MANIFEST = 'integration/controller-input-manifest.json'
REFUSED_DRIVER_SHA = '4bb6484c98a41e8d079de97f5f44eae061fd2c0ff8a87366202fe33201fa9a67'
REFUSED_BUNDLE_SHA = '4d982f68de64051aba1345716ca926918bf5f92bdfb48cf3c69cc493b4c72cd6'
REFUSED_CONTROLLER_SHA = '725a000ab299079e96192c6e81b3c2d809203d3052947a947f104d3d4d0f70b5'
REFUSED_MANIFEST = 'integration/controller-input-manifest-v2.json'
REFUSED_CONTROLLER_PATH = 'integration/integrate_candidate_v2.py'
FOLLOWUP_SHA = '13e84ec60d17cd039b0452b34d557305dd7fbb655c87efab6909bb53c24eced5'
ORIGINAL_NATIVE_RUNNER_SHA = '388111e2bf23e45e448c9451b46bb009df51a98c89ff8a4f3b22f9da1a69dd5d'
OBSERVER_RUNNER_SHA = '79d1397d97ad8fce27eb861b1ee70a30b22574a190059766f660259267885e46'
OBSERVER_CONTROLLER_SHA = '1075c69186b95bb8e3423693fbb931f375d5afa93dd6fc023a02715945d9e920'
OBSERVER_SUMMARY_SHA = 'd854150b8cf80efec0f06b7c7b5fe92522beee263fde0e151ccd237053887a35'
OBSERVER_COMMAND_SHA = '1e790dcb1c28abd6c90d327025aa6330b78354679b67fa3c3b6350d373bad307'
OBSERVER_STDOUT_SHA = '2835d032bdbdb420599092d03be394fa29d1c00894891d15bae065bc9d4cfef1'
BASELINE_RUNNER_SHA = 'ec1cf2eec81ef7c640b09a049f261560347c983e9ff019a6d7296ff1e2fd6862'
BASELINE_FOLLOWUP_RUNNER_SHA = 'cdc340416a6287ce1584f10cfc89e6927cfa206c129acdc3c7d6082dbb632e71'
BASELINE_FAILURE_SHA = '68977e5481de8af130df488d842bd018217de2c05267a66a8993b5486267ba97'
BASELINE_COMMANDS_SHA = '1974ece1864273d530bdd21aa6b1032dca74b15f8e31fbe7c23b8d43cb12cd07'
C2_TREE = '7c003a3d183ad33ff4f3349cbcce61564f73a2ba'
NATIVE_PREFIX = 'evidence/pon-followthrough-20261110-685a/native'
NATIVE_OBSERVATIONS = 'evidence/pon-followthrough-20261110-685a/native-observations.json'
SELECTED_C1 = '11c9562252d3cf56b423c7756569be0c669d9606'
SELECTED_C2 = C2
SELECTED_LINEAGE = (
    (BASE, '00479a98dabc6b1fd91a0ceef82ffbdbffb78067', None),
    (SELECTED_C1, '94e1b4f1718dec1b88bccd7e1996ba83ca29ff8a', BASE),
    (SELECTED_C2, C2_TREE, SELECTED_C1),
)
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_MEMBERS = 4096
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GH_PROMPT_DISABLED='1')


class Refusal(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw, usedforsecurity=False).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(Refusal('nonfinite JSON: ' + value)))


def relative(value):
    require(type(value) is str and not value.startswith('/') and '\\' not in value and '\0' not in value
            and all(part not in ('', '.', '..') for part in value.split('/')), 'unsafe relative artifact path')
    return value


def directory(path):
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'absolute normalized directory required')
    for item in (path, *path.parents):
        require(not item.is_symlink() and item.is_dir(), 'nonregular directory ancestry: ' + str(item))


def read_regular(path):
    require(path.is_absolute(), 'absolute regular path required')
    parts = path.parts[1:]
    require(parts and all(part not in ('', '.', '..') for part in parts), 'unsafe artifact path')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, 'nonregular or oversized artifact: ' + str(path))
        chunks, count = [], 0
        while count <= MAX_FILE:
            raw = os.read(descriptor, min(65536, MAX_FILE + 1 - count))
            if not raw:
                break
            chunks.append(raw)
            count += len(raw)
        after = os.fstat(descriptor)
        visible = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(count == before.st_size and count <= MAX_FILE and identity(before) == identity(after) == identity(visible),
                'artifact changed while reading: ' + str(path))
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def properties(raw):
    return {'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw)}


def parents(path):
    if not path.exists():
        parents(path.parent)
        path.mkdir(mode=0o755)
    directory(path)


def write_new(path, raw):
    parents(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def atomic_json(path, value):
    raw = encoded(value)
    if not path.exists():
        write_new(path, raw)
        return
    previous = read_regular(path)[0]
    temporary = path.parent / ('.publication-' + uuid.uuid4().hex)
    write_new(temporary, raw)
    try:
        require(read_regular(path)[0] == previous, 'publication receipt changed concurrently: ' + path.name)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def git(root, *args, allow_failure=False):
    result = subprocess.run(['git', '--no-replace-objects', *args], cwd=root, env=ENV, capture_output=True, timeout=90)
    require(allow_failure or result.returncode == 0, 'Git refused ' + ' '.join(args) + ': ' + result.stderr.decode(errors='replace')[-2000:])
    return result if allow_failure else result.stdout


def gtext(root, *args):
    return git(root, *args).decode().strip()


def tree_entries(root, revision):
    result = {}
    for row in git(root, 'ls-tree', '-r', '-z', revision).split(b'\0'):
        if row:
            metadata, path = row.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split()
            result[path.decode()] = {'mode': mode, 'kind': kind, 'git_blob': oid}
    return result


def selected_history(root, checkpoint=C2):
    """Verify only the complete reviewed lineage; never fetch or claim all history."""
    require(checkpoint == SELECTED_C2, "unreviewed selected checkpoint")
    history_shallow = git(root, "rev-parse", "--is-shallow-repository").strip()
    require(history_shallow in (b"true", b"false"), "unknown Git history depth")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "current HEAD is not an exact commit")
    require(git(root, "cat-file", "-t", head).strip() == b"commit", "current HEAD commit missing")
    selected_lineage = []
    for commit, expected_tree, parent in SELECTED_LINEAGE:
        require(git(root, "cat-file", "-t", commit).strip() == b"commit", "selected commit missing")
        raw = git(root, "cat-file", "commit", commit)
        require(hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw,
                            usedforsecurity=False).hexdigest() == commit, "selected commit bytes differ")
        header = raw.split(b"\n\n", 1)[0].splitlines()
        require([line[5:].decode() for line in header if line.startswith(b"tree ")] == [expected_tree],
                "selected commit tree header differs")
        require(git(root, "rev-parse", commit + "^{tree}").decode().strip() == expected_tree,
                "selected tree differs")
        if parent is not None:
            require([line[7:].decode() for line in header if line.startswith(b"parent ")] == [parent],
                    "selected raw parent segment differs")
            require(git(root, "rev-list", "--parents", "-n", "1", commit).decode().split() == [commit, parent],
                    "selected parent segment missing or differs")
        selected_lineage.append({"commit": commit, "tree": expected_tree, "required_parent": parent})
    git(root, "merge-base", "--is-ancestor", BASE, checkpoint)
    git(root, "merge-base", "--is-ancestor", checkpoint, head)
    require(git(root, "rev-parse", "HEAD").decode().strip() == head, "HEAD changed during selected-lineage check")
    require(all(not row or row.startswith(b"H ") for row in git(root, "ls-files", "-v", "-z").split(b"\0")),
            "hidden or nonordinary index entries refused")
    require(not git(root, "ls-files", "--deleted", "-z"), "tracked working file missing")
    return {"git_history_shallow": history_shallow == b"true", "complete_global_history_claimed": False,
            "selected_lineage": selected_lineage, "selected_lineage_complete": True,
            "selected_ancestry_head": head, "selected_source_ancestor_of_head": True}



def artifact_snapshot(root):
    """Collect every supported regular observation; name every excluded lock/index."""
    directory(root)
    result, exclusions, total = {}, [], 0
    def failed(error):
        raise error
    for parent, folders, files in os.walk(root, followlinks=False, onerror=failed):
        for name in folders:
            folder = Path(parent) / name
            require(not folder.is_symlink() and name not in ('.git', 'target', 'node_modules', '__pycache__'),
                    'unreviewed artifact directory: ' + str(folder))
        for name in sorted(files):
            path = Path(parent) / name
            name = relative(str(path.relative_to(root)))
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode), 'nonregular output artifact: ' + name)
            if path.suffix in ('.index', '.lock'):
                exclusions.append({'path': name, 'bytes': metadata.st_size, 'reason': 'temporary Git index or process lock; not copied'})
                continue
            require(path.suffix in ('.json', '.log', '.patch', '.txt', '.md', '.py', '.sh'), 'unreviewed output artifact type: ' + name)
            raw, mode = read_regular(path)
            require(not raw.startswith((b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'))
                    and b'\0' not in raw, 'binary file is not an observation artifact: ' + name)
            if path.suffix == '.json':
                strict_json(raw)
            total += len(raw)
            require(total <= MAX_TOTAL and len(result) < MAX_MEMBERS, 'observation collection bound exceeded')
            result[name] = {'raw': raw, 'original_mode': oct(mode), **properties(raw)}
    return result, exclusions


def snapshot_identity(files):
    return {name: {key: value for key, value in item.items() if key != 'raw'} for name, item in files.items()}


def check_command_references(files):
    """Verify recorded log hashes and include both sidecars for older unhashed records."""
    checked = []
    def verify(command_path, row, fallback=None):
        require(type(row) is dict and type(row.get('exit_code')) is int and type(row.get('argv')) is list,
                'invalid actual command record: ' + command_path)
        parent = Path(command_path).parent
        for stream in ('stdout', 'stderr'):
            record = row.get(stream)
            if record is None:
                require(fallback is not None, 'command has no original stream reference: ' + command_path)
                name = fallback + '.' + stream + '.log'
            else:
                require(type(record) is dict, 'malformed stream reference')
                name = relative(record['file'])
            target = str(parent / name)
            require(target in files, 'missing original command stream: ' + target)
            actual = files[target]
            if record is not None:
                require(type(record.get('bytes')) is int and record['bytes'] == actual['bytes']
                        and record.get('sha256') == actual['sha256'], 'recorded original stream differs: ' + target)
                if 'git_blob' in record:
                    require(record['git_blob'] == actual['git_blob'], 'recorded original stream Git blob differs: ' + target)
            checked.append({'command': command_path, 'stream': target, 'exit_code': row['exit_code'],
                            'prior_hash_recorded': record is not None})
    for name, item in files.items():
        if Path(name).name == 'commands.json':
            commands = strict_json(item['raw'])
            require(type(commands) is list, 'commands.json is not an array')
            for row in commands:
                verify(name, row)
        elif name.endswith('.command.json'):
            verify(name, strict_json(item['raw']), Path(name).name.removesuffix('.command.json'))
    return checked


def original_bracket(files, before, after, c3, tree):
    require(before in files and after in files and files[before]['raw'] == files[after]['raw'], 'original source bracket differs')
    value = strict_json(files[before]['raw'])
    require(value.get('schema') == 'trnm-ci-source-v1' and value.get('kind') == 'head'
            and value.get('tested_commit') == value.get('candidate') == c3 and value.get('tested_tree') == tree
            and value.get('tracked_worktree_verified') is True
            and value.get('tests_executed_by_identity_check') is False, 'source bracket identity or scope differs')


def failed_native_draft_scope(value):
    require(value.get('native_observation_complete') is True
            and value.get('native_full_suite_passed') is False and value.get('draft_only') is True
            and value.get('open_consensus_qualified') is False
            and value.get('production_activation') is False and value.get('security_status') == 'HOLD',
            'failed-native draft scope was changed or upgraded')


def validate_followup_summary(value):
    require(value.get('schema') == 'pon-native-failure-followup-v1'
            and value.get('source') == C2 and value.get('tree') == C2_TREE
            and value.get('recorder_sha256') == FOLLOWUP_SHA
            and value.get('observation_complete') is True and value.get('all_followup_checks_passed') is False
            and value.get('original_full_node_suite_passed') is False and value.get('full_suite_repeated') is False
            and value.get('all_prior_observations_retained') is True and value.get('source_mutations_performed') is False
            and value.get('open_consensus_qualified') is False and value.get('production_activation') is False
            and value.get('security_status') == 'HOLD', 'original v4 observation is incomplete or relabeled')
    require(value.get('prior_full_suite') == {'passed': 1285, 'failed': 2, 'ignored': 39, 'exit_code': 101},
            'original failed full-suite counts changed')
    labels = ('preflight', 'source-before', 'prior-source-identical', 'isolated-large-parent', 'isolated-inactive-page',
              'fresh-probe-tests', 'changed-owner-clippy', 'format-check', 'fresh-probe-build', 'fresh-probe-native',
              'fresh-probe-reader', 'fresh-reader-tests', 'source-after', 'source-identical')
    expected = [{'label': name, 'exit_code': 101 if name in ('isolated-large-parent', 'isolated-inactive-page') else 0}
                for name in labels]
    require(value.get('commands') == expected, 'v4 named command outcomes differ from the recorded failed cohort')


def validate_observations(controller, native, driver, root):
    parsed = lambda files, path: strict_json(files[path]['raw'])
    integrated, state = parsed(controller, 'summary.json'), parsed(controller, 'state.json')
    require(integrated.get('schema') == 'pon-followthrough-controller-summary-v2'
            and integrated.get('integration_complete') is True and integrated.get('requested_phase_complete') is True
            and integrated.get('state') == 'validated' and integrated.get('code_checkpoint_c2') == C2,
            'actual integration has not completed')
    c3, tree = integrated.get('binding_child_c3'), integrated.get('binding_child_tree')
    require(all(type(value) is str and re.fullmatch('[0-9a-f]{40}', value) for value in (c3, tree)), 'missing real C3 identity')
    require(state.get('schema') == 'pon-followthrough-controller-state-v2' and state.get('phase') == 'validated'
            and state.get('source_c2') == C2 and state.get('source_c3') == c3
            and state.get('expected_head') == c3 and state.get('prepared_tree') == tree
            and state.get('root') == str(root) and state.get('controller_sha256') == CONTROLLER_SHA,
            'controller completion state differs')
    for value in (integrated, state):
        failed_native_draft_scope(value)
    native_preflight = parsed(controller, 'native-preflight.json')
    require(native_preflight.get('schema') == 'pon-followthrough-native-observations-v2'
            and native_preflight.get('code_checkpoint', {}).get('commit') == C2
            and native_preflight.get('code_checkpoint', {}).get('tree') == C2_TREE
            and native_preflight.get('full_node_suite') == {'passed': 1285, 'failed': 2, 'ignored': 39, 'exit_code': 101}
            and native_preflight.get('original_v3_completed') is False
            and native_preflight.get('original_source_after_v3_created') is False
            and native_preflight.get('source_bracket_closed_by_followup') is True
            and native_preflight.get('followup_command_count') == 14,
            'derived native observation does not retain the actual failed cohort')
    failed_native_draft_scope(native_preflight)
    require(integrated.get('native_full_suites_repeated') is False and integrated.get('hosted_ci_observed_complete') is False,
            'integration scope differs')
    commands = parsed(controller, 'commands.json')
    require(type(commands) is list and integrated['commands_recorded'] == len(commands)
            and len({row['label'] for row in commands}) == len(commands)
            and all(row.get('cwd') == str(root) for row in commands), 'integration command count or identities differ')
    runs = state.get('validation_runs')
    require(type(runs) is list and runs and integrated.get('validation_runs') == runs
            and runs[-1].get('complete') is True and runs[-1].get('state') == 'finished', 'latest integration validation is not complete')
    last_path = relative(runs[-1]['summary'])
    last = parsed(controller, last_path)
    require(last.get('schema') == 'pon-followthrough-binding-child-checks-v2' and last.get('complete') is True
            and last.get('source_bracket_identical') is True and last.get('binding_child_c3') == c3
            and last.get('binding_child_tree') == tree and last.get('code_checkpoint_c2') == C2
            and last.get('hosted_ci_observed_complete') is False, 'last integration validation summary differs')
    failed_native_draft_scope(last)
    actual = {row['label']: row for row in commands}
    require(last.get('commands') and all(item['exit_code'] == 0 and item['label'] in actual
            and actual[item['label']]['exit_code'] == 0 for item in last['commands']), 'latest integration contains an unsuccessful command')
    prefix = last_path.removesuffix('-summary.json')
    plan = parsed(controller, prefix + '-planned-checks.json')
    require(plan.get('source') == c3 and plan.get('checks_already_passed') is False
            and plan.get('native_full_suites_repeated') is False and type(plan.get('checks')) is list,
            'original C3 check plan identity differs')
    expected_labels = [prefix + '-source-before'] + [prefix + '-' + row[0] for row in plan['checks']]
    expected_labels += [prefix + '-source-after', prefix + '-source-identical']
    require([row['label'] for row in last['commands']] == expected_labels
            and len(expected_labels) == len(set(expected_labels)), 'actual C3 checks do not close the original plan')
    for label, argv in plan['checks']:
        require(actual[prefix + '-' + label]['argv'] == argv, 'actual C3 command differs from its original plan')
    original_bracket(controller, prefix + '-source-before.json', prefix + '-source-after.json', c3, tree)
    child, source = parsed(native, 'summary.json'), parsed(native, 'source.json')
    require(child.get('schema') == 'pon-followthrough-binding-child-native-checks-v1'
            and child.get('complete') is True and child.get('strict_clippy_passed') is True, 'actual C3 native lint has not completed')
    for value in (source, child):
        require(value.get('code_checkpoint_c2') == C2 and value.get('binding_child_c3') == c3
                and value.get('binding_child_tree') == tree and value.get('native_changed_from_c2') == [INVENTORY]
                and value.get('cargo_graph_inputs_unchanged') is True and value.get('child_full_suites_repeated') is False
                and value.get('full_native_suites_execution_source') == C2 and value.get('recorder_sha256') == NATIVE_SHA
                and value.get('open_consensus_qualified') is False and value.get('production_activation') is False,
                'native child source, recorder or scope differs')
    native_commands = parsed(native, 'commands.json')
    require(child['commands'] == len(native_commands) == 6 and all(row['exit_code'] == 0 and row.get('cwd') == str(root) for row in native_commands),
            'C3 native command completion differs')
    by_name = {row['label']: row for row in native_commands}
    require(set(by_name) == {'preflight', 'source-before', 'locked-graph', 'changed-owner-clippy', 'source-after', 'source-identical'},
            'C3 native named command registry differs')
    require(by_name['changed-owner-clippy']['argv'] == ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml',
        '--locked', '--offline', '-p', 'trnm-pon-node', '-p', 'trnm-service-settlement', '-p', 'trnm-crypto-primitives',
        '--all-targets', '--', '-D', 'warnings'], 'strict Clippy command was weakened')
    require(by_name['locked-graph']['argv'] == ['cargo', 'metadata', '--manifest-path', 'trillionnium/Cargo.toml',
        '--locked', '--offline', '--format-version', '1'], 'locked native graph command differs')
    original_bracket(native, 'source-before.json', 'source-after.json', c3, tree)
    child_status = parsed(native, 'status.json')
    require(child_status.get('stage') == 'complete' and child_status.get('phase') == 'finished' and child_status.get('last_exit') == 0,
            'native runner is not in its completed state')
    driven, driver_status = parsed(driver, 'summary.json'), parsed(driver, 'status.json')
    require(driven.get('schema') == 'pon-followthrough-gated-driver-v3'
            and driven.get('complete') is True and driven.get('code_checkpoint_c2') == C2 and driven.get('binding_child_c3') == c3
            and driven.get('binding_child_tree') == tree and driven.get('integration_complete') is True
            and driven.get('binding_native_complete') is True and driven.get('published') is False
            and driven.get('production_activation') is False and driven.get('security_status') == 'HOLD', 'gated driver is not complete')
    failed_native_draft_scope(driven)
    require(driver_status.get('stage') == 'complete' and driver_status.get('phase') == 'finished'
            and driver_status.get('exit_code') == 0, 'gated driver completion status differs')
    for name in ('integrate', 'binding-native'):
        require(parsed(driver, name + '.command.json').get('exit_code') == 0, 'driver subprocess did not succeed: ' + name)
    bundle = parsed(driver, 'bundle.json')
    require(bundle.get('archive_sha256') == BUNDLE_SHA and bundle.get('member_count') == BUNDLE_MEMBERS
            and bundle.get('controller_sha256') == CONTROLLER_SHA and bundle.get('native_runner_sha256') == NATIVE_SHA,
            'driver bundle/recorder identity differs')
    observed_c2 = parsed(driver, 'observed-native-followup-summary.json')
    validate_followup_summary(observed_c2)
    require('observed-native-summary.json' not in driver, 'current driver borrowed the old all-pass summary name')
    require('validate_binding_native.py' in driver and driver['validate_binding_native.py']['sha256'] == NATIVE_SHA,
            'original native recorder bytes missing from driver output')
    return {'code_checkpoint_c2': C2, 'binding_child_c3': c3, 'binding_child_tree': tree,
            'latest_integration_summary': last_path, 'integration_command_count': len(commands),
            'prior_nonzero_integration_commands': [{'label': row['label'], 'exit_code': row['exit_code']}
                for row in commands if row['exit_code'] != 0], 'c3_native_command_count': 6,
            'strict_clippy_passed': True, 'child_full_native_suites_repeated': False,
            'native_observation_complete': True, 'native_full_suite_passed': False, 'draft_only': True,
            'full_node_suite': native_preflight['full_node_suite'],
            'followup_command_count': 14, 'followup_nonzero_exact_tests': ['isolated-large-parent', 'isolated-inactive-page'],
            'followup_all_checks_passed': False, 'original_v3_completed': False,
            'hosted_ci_observed_complete': False, 'open_consensus_qualified': False,
            'production_activation': False, 'security_status': 'HOLD'}, state


def bundle_payload(driver_raw, *, historical=False, refused=False):
    require(not (historical and refused), 'two distinct historical cohorts cannot be combined')
    driver_sha = HISTORICAL_DRIVER_SHA if historical else REFUSED_DRIVER_SHA if refused else DRIVER_SHA
    archive_sha = HISTORICAL_BUNDLE_SHA if historical else REFUSED_BUNDLE_SHA if refused else BUNDLE_SHA
    member_count = 14 if historical else BUNDLE_MEMBERS
    require(sha(driver_raw) == driver_sha, 'gated driver source differs from frozen identity')
    values = [node.value for node in ast.parse(driver_raw).body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == 'ARCHIVE' for target in node.targets)]
    require(len(values) == 1 and isinstance(values[0], ast.Call) and len(values[0].args) == 1
            and isinstance(values[0].args[0], ast.Constant) and isinstance(values[0].args[0].value, str), 'driver archive literal unavailable')
    raw = base64.b64decode(values[0].args[0].value, validate=True)
    require(sha(raw) == archive_sha, 'frozen driver archive differs')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len({item.name for item in members}) == member_count
                and all(item.isfile() and relative(item.name) for item in members)
                and sum(item.size for item in members) < 512 * 1024, 'frozen bundle member scope differs')
        return {item.name: archive.extractfile(item).read() for item in members}


def validate_retained_native(original, followup, original_root, followup_root, root):
    """Reconcile the retained failed execution with the independent v4 bracket."""
    parsed = lambda files, name: strict_json(files[name]['raw'])
    require('summary-v3.json' not in original and 'source-after-v3.json' not in original,
            'the aborted v3 execution gained a nonexistent completion receipt')
    source = parsed(original, 'source-v3.json')
    require(source.get('baseline') == BASE and source.get('prior_code_commit') == SELECTED_C1
            and source.get('commit') == C2 and source.get('tree') == C2_TREE and source.get('clean') is True,
            'original failed native source differs')
    summary, followup_source = parsed(followup, 'summary.json'), parsed(followup, 'source.json')
    validate_followup_summary(summary)
    require(all(summary.get(key) == value for key, value in followup_source.items()),
            'v4 source metadata differs from its original summary')
    require(summary.get('prior_commands_sha256') == original['commands.json']['sha256']
            and summary.get('prior_full_suite_sha256') == original['node-library-v3.stdout.log']['sha256'],
            'v4 does not bind the complete original failed records')
    before = original['source-before-v3.json']['raw']
    require(before == followup['source-before.json']['raw'] == followup['source-after.json']['raw'],
            'v4 source bracket does not close the original v3 source observation')
    original_bracket(followup, 'source-before.json', 'source-after.json', C2, C2_TREE)
    rows = parsed(original, 'commands.json')
    require(type(rows) is list and rows and rows[-1].get('label') == 'node-library-v3'
            and rows[-1].get('exit_code') == 101, 'original command cohort no longer ends at the failed full suite')
    counts = re.findall(rb'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',
                        original['node-library-v3.stdout.log']['raw'], re.M)
    require(counts and counts[-1] == (b'1285', b'2', b'39'), 'retained full-suite denominator differs')
    later = parsed(followup, 'commands.json')
    require(type(later) is list and len(later) == 14
            and [{'label': row.get('label'), 'exit_code': row.get('exit_code')} for row in later] == summary['commands']
            and all(row.get('cwd') == str(root) for row in later), 'actual v4 command records differ from the summary')
    cargo = ['cargo', 'test', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline']
    cases = {
        'isolated-large-parent': 'store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner',
        'isolated-inactive-page': 'store::native_authenticated_tests::native_inactive_page_parents_use_checked_material_without_early_activation',
    }
    verify = ['python3', '-B', VERIFY, '--kind', 'head', '--expected-head', C2, '--output']
    binary = summary.get('binary', {})
    require(binary.get('exit_code') == 0 and re.fullmatch('[0-9a-f]{64}', binary.get('sha256', ''))
            and type(binary.get('path')) is str and binary['path'].endswith('/release/examples/pon_fresh_rejection_cost'),
            'actual release-probe identity is missing')
    expected = {
        'preflight': ['bash', 'scripts/project-preflight.sh'],
        'source-before': verify + [str(followup_root / 'source-before.json')],
        'prior-source-identical': ['cmp', str(original_root / 'source-before-v3.json'), str(followup_root / 'source-before.json')],
        **{label: cargo + ['-p', 'trnm-pon-node', '--lib', name, '--', '--exact', '--nocapture'] for label, name in cases.items()},
        'fresh-probe-tests': cargo + ['--release', '-p', 'trnm-crypto-primitives', '--example', 'pon_fresh_rejection_cost'],
        'changed-owner-clippy': ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline',
            '-p', 'trnm-pon-node', '-p', 'trnm-service-settlement', '-p', 'trnm-crypto-primitives', '--all-targets', '--', '-D', 'warnings'],
        'format-check': ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'],
        'fresh-probe-build': ['cargo', 'build', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline',
            '--release', '-p', 'trnm-crypto-primitives', '--example', 'pon_fresh_rejection_cost'],
        'fresh-probe-native': [binary['path']],
        'fresh-probe-reader': ['python3', '-B', 'scripts/pon_fresh_rejection_report.py',
            str(followup_root / 'fresh-probe-native.stdout.log'), '--raw-sha256', followup['fresh-probe-native.stdout.log']['sha256']],
        'fresh-reader-tests': ['python3', '-B', 'scripts/ci/test_fresh_rejection_report.py', '-v'],
        'source-after': verify + [str(followup_root / 'source-after.json')],
        'source-identical': ['cmp', str(followup_root / 'source-before.json'), str(followup_root / 'source-after.json')],
    }
    require([row['label'] for row in later] == list(expected)
            and all(row.get('argv') == expected[row['label']] for row in later), 'v4 original command arguments changed')
    for label in cases:
        raw = followup[label + '.stdout.log']['raw'] + followup[label + '.stderr.log']['raw']
        require(b'PUBLIC_MUTATION_CPU_BUDGET' in raw and b'OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH' not in raw,
                'v4 exact-test failure was confused with the original full-run diagnostic: ' + label)
    report = parsed(followup, 'fresh-probe-reader.stdout.log')
    require(report.get('schema') == 'pon-fresh-rejection-summary-v1' and report.get('complete_campaign') is True
            and report.get('samples') == report.get('independent_relation_replays') == 64
            and report.get('raw_sha256') == followup['fresh-probe-native.stdout.log']['sha256']
            and report.get('all_legal_strategy_cost_bound') is None
            and all(report.get(name) is False for name in ('hardness_qualified', 'native_source_binary_resource_authenticated',
                'production_activation', 'public_service_measured', 'worst_case_rejection_qualified')),
            'fresh probe scope or original 64-sample denominator differs')
    status = parsed(followup, 'status.json')
    require(status.get('stage') == 'complete-observation' and status.get('phase') == 'finished'
            and status.get('exit_code') == 0 and status.get('source') == C2
            and status.get('original_full_node_suite_passed') is False, 'v4 terminal observation is incomplete')
    return {'original_command_count': len(rows), 'followup_command_count': 14,
            'original_directory': str(original_root), 'followup_directory': str(followup_root),
            'original_full_node_suite': summary['prior_full_suite'], 'native_full_suite_passed': False,
            'native_observation_complete': True, 'draft_only': True,
            'followup_exact_error': 'PUBLIC_MUTATION_CPU_BUDGET',
            'full_run_and_exact_run_failures_equated': False,
            'followup_recorder_sha256': FOLLOWUP_SHA, 'original_commands_sha256': original['commands.json']['sha256'],
            'followup_summary_sha256': followup['summary.json']['sha256'], 'source_bracket_closed_by_followup': True}


def validate_historical_driver(files):
    parsed = lambda name: strict_json(files[name]['raw'])
    require(not {'summary.json', 'observed-native-summary.json', 'integrate.command.json', 'binding-native.command.json'} & files.keys(),
            'historical driver gained an execution or completion after its retained refusal')
    failure, status, bundle = parsed('failure.json'), parsed('status.json'), parsed('bundle.json')
    require(failure.get('complete') is False and failure.get('published') is False
            and failure.get('security_status') == 'HOLD' and 'node-library-v3' in failure.get('reason', '')
            and '101' in failure.get('reason', '') and status.get('stage') == 'driver'
            and status.get('phase') == 'failed' and status.get('exit_code') == 2,
            'historical driver is not the actual failed native-v3 gate')
    require(bundle.get('archive_sha256') == HISTORICAL_BUNDLE_SHA and bundle.get('member_count') == 14
            and bundle.get('controller_sha256') == HISTORICAL_CONTROLLER_SHA
            and bundle.get('native_runner_sha256') == NATIVE_SHA
            and files['validate_binding_native.py']['sha256'] == NATIVE_SHA,
            'historical frozen bundle or native recorder differs')
    return {'complete': False, 'driver_exit_code': 2, 'failed_native_label': 'node-library-v3',
            'failed_native_exit_code': 101, 'original_failure_sha256': files['failure.json']['sha256'],
            'driver_sha256': HISTORICAL_DRIVER_SHA, 'archive_sha256': HISTORICAL_BUNDLE_SHA,
            'historical_controller_sha256': HISTORICAL_CONTROLLER_SHA, 'published': False}


def validate_refused_integration(driver, controller, root, inputs, integration, original, followup):
    """Keep the exact driver-02 parser refusal separate from successful C3 work."""
    parsed = lambda files, name: strict_json(files[name]['raw'])
    require(set(controller) == {'failure.json', 'status.json'},
            'refused controller-02 gained an execution, source binding or completion receipt')
    failure, status = parsed(controller, 'failure.json'), parsed(controller, 'status.json')
    require(failure.get('status') == 'REFUSE_OR_ACTUAL_FAILURE'
            and failure.get('reason') == 'original native denominator differs: node-library-v3'
            and failure.get('requested_phase') == 'all' and failure.get('no_automatic_rollback') is True
            and failure.get('no_push_or_activation') is True and failure.get('security_status') == 'HOLD'
            and status.get('stage') == 'preflight' and status.get('phase') == 'failed'
            and status.get('last_exit') == 2 and status.get('current_head') is None
            and status.get('security_status') == 'HOLD', 'controller-02 refusal differs from the actual parser failure')
    require(not {'summary.json', 'observed-native-summary.json', 'binding-native.command.json',
                 'binding-native.stdout.log', 'binding-native.stderr.log'} & driver.keys(),
            'driver-02 gained a native-child execution or completion after its refusal')
    driver_failure, driver_status, bundle = (parsed(driver, name) for name in ('failure.json', 'status.json', 'bundle.json'))
    require(driver_failure.get('complete') is False and driver_failure.get('published') is False
            and driver_failure.get('reason') == "RuntimeError('integrate actual exit 2')"
            and driver_failure.get('no_automatic_rollback') is True and driver_failure.get('security_status') == 'HOLD'
            and driver_status.get('stage') == 'driver' and driver_status.get('phase') == 'failed'
            and driver_status.get('exit_code') == 2, 'driver-02 is not the recorded integration refusal')
    require(bundle.get('archive_sha256') == REFUSED_BUNDLE_SHA and bundle.get('member_count') == 14
            and bundle.get('controller_sha256') == REFUSED_CONTROLLER_SHA and bundle.get('native_runner_sha256') == NATIVE_SHA
            and driver['validate_binding_native.py']['sha256'] == NATIVE_SHA,
            'refused driver-02 frozen source identities differ')
    validate_followup_summary(parsed(driver, 'observed-native-followup-summary.json'))
    command = parsed(driver, 'integrate.command.json')
    require(command.get('exit_code') == 2 and command.get('cwd') == str(root)
            and command.get('argv') == ['python3', '-B', str(inputs / REFUSED_CONTROLLER_PATH),
                '--phase', 'all', '--root', str(root), '--inputs', str(inputs), '--native-validation', str(original),
                '--native-followup', str(followup), '--output', str(integration)],
            'refused driver-02 command identity differs')
    require(parsed(driver, 'integrate.stderr.log') == failure,
            'refused controller output differs from the original failure record')
    return {'driver_attempt': '02', 'controller_complete': False, 'driver_complete': False,
            'native_child_executed': False, 'c3_created': False, 'controller_exit_code': 2,
            'controller_reason': failure['reason'], 'controller_failure_sha256': controller['failure.json']['sha256'],
            'driver_failure_sha256': driver['failure.json']['sha256'], 'driver_sha256': REFUSED_DRIVER_SHA,
            'archive_sha256': REFUSED_BUNDLE_SHA, 'controller_sha256': REFUSED_CONTROLLER_SHA,
            'observed_followup_summary_sha256': driver['observed-native-followup-summary.json']['sha256'],
            'published': False, 'security_status': 'HOLD'}


def validate_baseline_observations(initial, followup, initial_root, followup_root, root):
    """Retain the separate exact-baseline selected tests without crediting C2."""
    parsed = lambda files, path: strict_json(files[path]['raw'])
    require(not {'source.json', 'summary.json', 'source-before.json', 'source-after.json'} & initial.keys(),
            'initial baseline guard refusal gained test or source receipts')
    require(initial['failure.json']['sha256'] == BASELINE_FAILURE_SHA
            and initial['commands.json']['sha256'] == BASELINE_COMMANDS_SHA,
            'initial baseline observation differs from the retained guard refusal')
    creation = parsed(initial, 'commands.json')
    require(parsed(initial, 'failure.json').get('reason') == 'shallow source refused'
            and len(creation) == 1 and creation[0].get('label') == 'create-isolated-worktree'
            and creation[0].get('exit_code') == 0, 'initial baseline executed more than its retained checkout action')
    summary, source = parsed(followup, 'summary.json'), parsed(followup, 'source.json')
    require(summary.get('schema') == 'pon-baseline-original-two-test-observation-v1'
            and summary.get('observation_complete') is True and summary.get('all_baseline_tests_passed') is False
            and 'full_library_suite_passed' in summary and summary['full_library_suite_passed'] is None
            and summary.get('full_library_suite_executed') is False and summary.get('causal_attribution_established') is False
            and summary.get('source_mutated') is False and summary.get('budgets_or_assertions_changed') is False
            and summary.get('source_bracket_identical') is True and summary.get('commands') == 9
            and summary.get('open_consensus_qualified') is False and summary.get('production_activation') is False
            and summary.get('security_status') == 'HOLD', 'baseline selected-test scope is incomplete or upgraded')
    require(all(summary.get(name) == value for name, value in source.items())
            and source.get('baseline_commit') == source.get('actual_commit') == BASE
            and source.get('actual_tree') == source.get('expected_tree') == SELECTED_LINEAGE[0][1]
            and source.get('source_provider_worktree') == str(root) and source.get('source_provider_head_at_start') == C2
            and source.get('recorder_sha256') == BASELINE_FOLLOWUP_RUNNER_SHA
            and source.get('prior_creation_observation') == str(initial_root)
            and source.get('prior_failure_sha256') == BASELINE_FAILURE_SHA
            and source.get('prior_commands_sha256') == BASELINE_COMMANDS_SHA
            and source.get('all_index_entries_H') is True and source.get('tracked_entries') == 27660
            and type(source.get('git_history_shallow')) is bool, 'actual baseline source/recorder differs')
    original_bracket(followup, 'source-before.json', 'source-after.json', BASE, SELECTED_LINEAGE[0][1])
    tests = (
        ('legacy-large-parent', 'store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner', 0, [1, 0, 0, 0, 1321]),
        ('inactive-page-parents', 'store::native_authenticated_tests::native_inactive_page_parents_use_checked_material_without_early_activation', 101, [0, 1, 0, 0, 1321]),
    )
    expected_tests = [{'label': label, 'full_name': name, 'exit_code': code,
                       'exact_single_test_execution_observed': True, 'reported_counts': counts}
                      for label, name, code, counts in tests]
    require(summary.get('tests') == expected_tests, 'baseline pass/fail identity or denominator changed')
    verify = ['python3', '-B', VERIFY, '--kind', 'head', '--expected-head', BASE, '--output']
    expected = {
        'preflight': ['bash', 'scripts/project-preflight.sh'],
        'source-before': verify + [str(followup_root / 'source-before.json')],
        'rustc-version': ['rustc', '-Vv'], 'cargo-version': ['cargo', '-V'],
        'locked-offline-graph': ['cargo', 'metadata', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline', '--format-version', '1'],
        **{label: ['cargo', 'test', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline',
            '-p', 'trnm-pon-node', '--lib', name, '--', '--exact', '--nocapture'] for label, name, _, _ in tests},
        'source-after': verify + [str(followup_root / 'source-after.json')],
        'source-identical': ['cmp', str(followup_root / 'source-before.json'), str(followup_root / 'source-after.json')],
    }
    commands = parsed(followup, 'commands.json')
    require(type(commands) is list and [row['label'] for row in commands] == list(expected)
            and all(row.get('argv') == expected[row['label']] and row.get('cwd') == source['worktree']
                    and row.get('exit_code') == (101 if row['label'] == 'inactive-page-parents' else 0) for row in commands),
            'baseline original nine command records differ')
    for label, name, code, counts in tests:
        raw = followup[label + '.stdout.log']['raw']
        summaries = re.findall(rb'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', raw, re.M)
        require(len(summaries) == 1 and list(map(int, summaries[0])) == counts
                and b'running 1 test\n' in raw
                and re.search(rb'^test ' + re.escape(name.encode()) + rb' \.\.\. ' + (b'ok' if code == 0 else b'FAILED') + rb'$', raw, re.M),
                'baseline selected test was not actually observed: ' + label)
    failure_text = followup['inactive-page-parents.stdout.log']['raw'] + followup['inactive-page-parents.stderr.log']['raw']
    require(b'PUBLIC_MUTATION_CPU_BUDGET' in failure_text and b'OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH' not in failure_text,
            'baseline inactive-page failure is not the distinct recorded CPU budget refusal')
    status, failure = parsed(followup, 'status.json'), parsed(followup, 'failure.json')
    require(status.get('stage') == 'complete' and status.get('phase') == 'tests-failed' and status.get('last_exit') == 101
            and status.get('current_head') == BASE and failure.get('observation_complete') is True
            and failure.get('exit_code') == 101 and failure.get('tests') == expected_tests,
            'baseline failed observation did not reach its recorded terminal state')
    return {'baseline_commit': BASE, 'baseline_tree': SELECTED_LINEAGE[0][1],
            'initial_observation_tests_executed': False, 'initial_guard_reason': 'shallow source refused',
            'selected_tests_observed': 2, 'all_baseline_tests_passed': False, 'full_library_suite_passed': None,
            'full_library_suite_executed': False, 'observation_complete': True, 'tests': expected_tests,
            'inactive_page_error': 'PUBLIC_MUTATION_CPU_BUDGET', 'same_error_as_c2_full_run_claimed': False,
            'causal_attribution_established': False, 'counted_as_c2_execution': False,
            'initial_runner_sha256': BASELINE_RUNNER_SHA, 'followup_runner_sha256': BASELINE_FOLLOWUP_RUNNER_SHA,
            'git_history_shallow': source['git_history_shallow'], 'complete_global_history_claimed': False,
            'summary_sha256': followup['summary.json']['sha256'], 'security_status': 'HOLD'}


def validate_readonly_observer(files, root, imported_controller, original, followup):
    """This is an original parser audit, never C3 integration or a native rerun."""
    require(set(files) == {'source.json', 'command.json', 'status.json', 'summary.json',
                           'validate-native.stdout.log', 'validate-native.stderr.log'},
            'readonly parser audit member roster differs')
    require(files['summary.json']['sha256'] == OBSERVER_SUMMARY_SHA
            and files['command.json']['sha256'] == OBSERVER_COMMAND_SHA
            and files['validate-native.stdout.log']['sha256'] == OBSERVER_STDOUT_SHA,
            'readonly parser audit no longer has its original bytes')
    parsed = lambda name: strict_json(files[name]['raw'])
    summary, source, command, status = (parsed(name) for name in ('summary.json', 'source.json', 'command.json', 'status.json'))
    require(summary.get('schema') == 'pon-native-observer-actual-receipts-audit-v1'
            and summary.get('complete') is True and summary.get('parser_exit_code') == 0
            and summary.get('original_commands') == 39 and summary.get('followup_commands') == 14
            and summary.get('raw_members') == 121 and summary.get('project_mutations_performed') is False
            and summary.get('native_tests_executed') is False and summary.get('c3_created') is False
            and summary.get('native_full_suite_passed') is False and summary.get('production_activation') is False
            and summary.get('security_status') == 'HOLD', 'readonly parser audit scope was upgraded')
    require(all(summary.get(key) == value for key, value in source.items())
            and source.get('code_checkpoint') == C2 and source.get('tree') == C2_TREE
            and source.get('controller_sha256') == OBSERVER_CONTROLLER_SHA and source.get('controller_bytes') == 81870
            and source.get('recorder_sha256') == OBSERVER_RUNNER_SHA
            and source.get('original_directory') == str(original) and source.get('followup_directory') == str(followup),
            'readonly parser audit source differs')
    require(command.get('label') == 'validate-native-actual-originals' and command.get('exit_code') == 0
            and command.get('cwd') == str(root) and type(command.get('argv')) is list and len(command['argv']) == 8
            and command['argv'][:3] == ['python3', '-B', '-c']
            and command['argv'][4:] == [str(imported_controller), str(original), str(followup), str(root)],
            'readonly parser audit original invocation differs')
    for stream in ('stdout', 'stderr'):
        recorded = command[stream]
        require(recorded.get('file') == 'validate-native.' + stream + '.log'
                and recorded.get('sha256') == files[recorded['file']]['sha256']
                and recorded.get('bytes') == files[recorded['file']]['bytes'],
                'readonly parser audit original stream differs: ' + stream)
    report = parsed('validate-native.stdout.log')
    failed_native_draft_scope(report.get('observations', {}))
    require(type(report.get('members')) is dict and len(report['members']) == 121
            and report['observations'].get('original_command_count') == 39
            and report['observations'].get('followup_command_count') == 14,
            'readonly parser audit original command/member denominator differs')
    require(status.get('stage') == 'validate-native-actual-originals' and status.get('phase') == 'finished'
            and status.get('last_exit') == 0 and status.get('controller_sha256') == OBSERVER_CONTROLLER_SHA
            and status.get('code_checkpoint') == C2 and status.get('native_full_suite_passed') is False
            and status.get('security_status') == 'HOLD', 'readonly parser audit did not finish in its recorded scope')
    return {'complete': True, 'scope': 'readonly original receipt parser only', 'parser_exit_code': 0,
            'original_commands': 39, 'followup_commands': 14, 'raw_members': 121,
            'native_tests_executed': False, 'project_mutations_performed': False, 'c3_created': False,
            'native_full_suite_passed': False, 'controller_sha256': OBSERVER_CONTROLLER_SHA,
            'recorder_sha256': OBSERVER_RUNNER_SHA, 'summary_sha256': OBSERVER_SUMMARY_SHA,
            'security_status': 'HOLD'}


def evidence_additions(base, final, expected):
    require(base.keys() <= final.keys(), 'C4 deleted a C3 path')
    require(all(final[path] == value for path, value in base.items()), 'C4 changed a pre-existing C3 blob or mode')
    added = set(final) - set(base)
    require(added == set(expected) and all(path.startswith(PREFIX + '/') for path in added), 'C4 additions exceed exact evidence members')
    for path, value in expected.items():
        require(final[path] == {'mode': '100644', 'kind': 'blob', 'git_blob': value['git_blob']}, 'staged evidence blob/mode differs: ' + path)


class Publisher:
    def __init__(self, args):
        self.args, self.owns_output = args, False
        require(V2_IDENTITIES_FROZEN and all(re.fullmatch('[0-9a-f]{64}', value)
                for value in (CONTROLLER_SHA, DRIVER_SHA, BUNDLE_SHA)), 'v2 publication identities are not frozen')
        self.root, self.inputs, self.integration, self.native, self.driver, self.out = (
            args.root, args.inputs, args.integration_output, args.final_native_output, args.driver_output, args.output)
        self.historical_inputs, self.historical_driver = args.historical_inputs, args.historical_driver_output
        self.refused_inputs, self.refused_driver, self.refused_integration = (
            args.refused_inputs, args.refused_driver_output, args.refused_integration_output)
        self.baseline, self.baseline_followup = args.baseline_output, args.baseline_followup_output
        self.baseline_runner, self.baseline_followup_runner = args.baseline_runner, args.baseline_followup_runner
        self.native_followup_runner = args.native_followup_runner or self.inputs.parent / 'run_native_followup_v4.py'
        self.original_native_runner = args.original_native_runner or self.inputs.parent / 'run_native_validation_v3.py'
        self.observer_audit = args.observer_audit_output or self.inputs.parent / 'native-observer-audit-03'
        self.observer_runner = args.observer_audit_runner or self.inputs.parent / 'run_native_observer_audit_v3.py'
        self.observer_controller = args.observer_audit_controller or self.inputs.parent / 'integrate_candidate_v3_observer.py'
        self.driver_script = args.driver_script or self.inputs.parent / 'remote_integration_driver_03.py'
        self.historical_driver_script = args.historical_driver_script or self.historical_inputs.parent / 'remote_integration_driver_01.py'
        self.refused_driver_script = args.refused_driver_script or self.refused_inputs.parent / 'remote_integration_driver_02.py'
        input_directories = (self.inputs, self.integration, self.native, self.driver, self.historical_inputs,
                             self.historical_driver, self.refused_inputs, self.refused_driver, self.refused_integration,
                             self.baseline, self.baseline_followup, self.observer_audit)
        for path in (self.root, *input_directories):
            directory(path)
        directory(self.out.parent)
        require(not any(os.environ.get(name) for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
            'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT')), 'external Git override refused')
        require(all(not path.is_relative_to(self.root) for path in (*input_directories, self.out)),
                'publication inputs/receipts must be outside the checkout')
        require(all(not self.out.is_relative_to(path) and not path.is_relative_to(self.out)
                    for path in input_directories), 'publication receipt directory overlaps an input')
        require(self.driver != self.historical_driver and self.inputs != self.historical_inputs,
                'current and historical driver inputs must remain separate')
        require(len({self.driver, self.historical_driver, self.refused_driver}) == 3
                and len({self.inputs, self.historical_inputs, self.refused_inputs}) == 3
                and self.integration != self.refused_integration, 'the refused attempt-02 cohort must remain separate')
        require(self.baseline != self.baseline_followup, 'initial and followup baseline observations must remain separate')
        require(gtext(self.root, 'rev-parse', '--show-toplevel') == str(self.root), 'real Git worktree root required')
        self.history = selected_history(self.root)
        sparse = git(self.root, 'config', '--bool', 'core.sparseCheckout', allow_failure=True)
        require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b'', b'false'), 'sparse checkout refused')
        require(all(not row or row.startswith(b'H ') for row in git(self.root, 'ls-files', '-v', '-z').split(b'\0')),
                'nonordinary or hidden index entries refused')
        self.script_hash = sha(read_regular(Path(__file__).absolute())[0])
        identity = {name: str(getattr(self, name)) for name in ('root', 'inputs', 'integration', 'native', 'driver',
                    'historical_inputs', 'historical_driver', 'driver_script', 'historical_driver_script',
                    'refused_inputs', 'refused_driver', 'refused_integration', 'refused_driver_script',
                    'baseline', 'baseline_followup', 'baseline_runner', 'baseline_followup_runner',
                    'native_followup_runner', 'original_native_runner')}
        identity.update({name: str(getattr(self, name)) for name in ('observer_audit', 'observer_runner', 'observer_controller')})
        if self.out.exists():
            directory(self.out)
            self.state = strict_json(read_regular(self.out / 'state.json')[0])
            self.commands = strict_json(read_regular(self.out / 'commands.json')[0])
            require(self.state.get('schema') == 'pon-followthrough-publication-state-v2'
                    and self.state.get('input_directories') == identity and self.state.get('publisher_sha256') == self.script_hash,
                    'publication resume identity differs; do not create another write key')
        else:
            require(args.phase in ('prepare', 'all-local'), 'publication must start with prepare')
            self.out.mkdir(mode=0o755)
            self.commands = []
            self.state = {'schema': 'pon-followthrough-publication-state-v2', 'phase': 'starting',
                'input_directories': identity, 'publisher_sha256': self.script_hash, 'expected_files': {},
                'pending_write': None, 'security_status': 'HOLD', 'open_consensus_qualified': False, 'production_activation': False,
                'native_full_suite_passed': False, 'draft_only': True}
            self.save()
        self.lock = os.open(self.out / 'publication.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        require(stat.S_ISREG(os.fstat(self.lock).st_mode), 'publication lock is not regular')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owns_output = True

    def save(self):
        atomic_json(self.out / 'state.json', self.state)
        atomic_json(self.out / 'commands.json', self.commands)

    def status(self, stage, phase, code=None):
        atomic_json(self.out / 'status.json', {'schema': 'pon-followthrough-publication-status-v2', 'stage': stage,
            'phase': phase, 'exit_code': code, 'recorded_unix_ns': time.time_ns(),
            'binding_child_c3': self.state.get('c3'), 'evidence_child_c4': self.state.get('c4'),
            'pending_write': self.state.get('pending_write'), 'security_status': 'HOLD',
            'native_observation_complete': self.state.get('observations', {}).get('native_observation_complete', False),
            'native_full_suite_passed': False, 'draft_only': True})

    def run(self, label, argv, *, required=True, timeout=900, input_bytes=None):
        label = f'{len(self.commands) + 1:03d}-' + label
        require(re.fullmatch('[A-Za-z0-9_.-]+', label) is not None, 'unsafe command label')
        stdout, stderr = self.out / (label + '.stdout.log'), self.out / (label + '.stderr.log')
        start, error = time.time_ns(), None
        self.status(label, 'running')
        if input_bytes is not None:
            require(type(input_bytes) is bytes, 'explicit command stdin must be bytes')
            write_new(self.out / (label + '.stdin.txt'), input_bytes)
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                result = subprocess.run(argv, cwd=self.root, env=ENV, input=input_bytes,
                                        stdout=out, stderr=err, timeout=timeout, check=False)
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as failure:
                error = str(failure)
                err.write(('publication recorder execution failure: ' + error + '\n').encode())
                code = 124 if isinstance(failure, subprocess.TimeoutExpired) else 127
        row = {'label': label, 'argv': [str(x) for x in argv], 'cwd': str(self.root), 'exit_code': code,
               'start_unix_ns': start, 'end_unix_ns': time.time_ns(), 'launch_error': error}
        for stream, path in (('stdout', stdout), ('stderr', stderr)):
            row[stream] = {'file': path.name, **properties(read_regular(path)[0])}
        if input_bytes is not None:
            row['stdin'] = {'file': label + '.stdin.txt', **properties(input_bytes)}
        self.commands.append(row); self.save()
        self.status(label, 'finished' if code == 0 else 'failed', code)
        require(not required or code == 0, 'actual command failed; raw output retained: ' + label)
        return row

    def output_json(self, command):
        return strict_json(read_regular(self.out / command['stdout']['file'])[0])

    def current_branch(self):
        branch = gtext(self.root, 'symbolic-ref', '--short', 'HEAD')
        git(self.root, 'check-ref-format', '--branch', branch)
        require(branch not in ('main', 'master', PR_BASE), 'protected or base branch cannot receive the evidence commit')
        return branch

    def verify_tree(self, revision):
        evidence_additions(tree_entries(self.root, self.state['c3']), tree_entries(self.root, revision), self.state['expected_files'])
        for path, expected in self.state['expected_files'].items():
            require(properties(git(self.root, 'show', revision + ':' + path)) == expected, 'Git stored evidence bytes differ: ' + path)

    def working_guard(self, *, allow_partial=False):
        require(self.current_branch() == self.state['branch'], 'root branch changed')
        require(gtext(self.root, 'rev-parse', 'HEAD') == self.state['expected_head'], 'HEAD changed outside publication')
        require(all(not row or row.startswith(b'H ') for row in git(self.root, 'ls-files', '-v', '-z').split(b'\0')),
                'index concealment flags changed during publication')
        if self.state['phase'] not in ('starting', 'preparing', 'prepared', 'committing'):
            require(gtext(self.root, 'write-tree') == self.state['prepared_tree'], 'C4 index changed outside publication')
        changed = {x.decode() for x in (git(self.root, 'diff', '--name-only', '-z', 'HEAD', '--')
                   + git(self.root, 'ls-files', '--others', '--exclude-standard', '-z')).split(b'\0') if x}
        require(changed <= set(self.state['expected_files']), 'unreviewed working-tree change')
        for path, expected in self.state['expected_files'].items():
            target = self.root / path
            if allow_partial and not target.exists():
                require(not target.is_symlink(), 'dangling artifact alias')
                continue
            require(properties(read_regular(target)[0]) == expected, 'publication evidence changed: ' + path)

    def prepare(self):
        require(self.state['phase'] in ('starting', 'preparing'), 'prepare cannot replace an existing completed stage')
        self.status('prepare', 'running')
        lock = os.open(self.integration / 'controller.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        require(stat.S_ISREG(os.fstat(lock).st_mode), 'controller lock is not regular')
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        try:
            controller, exclusions_c = artifact_snapshot(self.integration)
            native, exclusions_n = artifact_snapshot(self.native)
            driver, exclusions_d = artifact_snapshot(self.driver)
            historical_driver, exclusions_h = artifact_snapshot(self.historical_driver)
            historical_outcome = validate_historical_driver(historical_driver)
            refused_driver, exclusions_rd = artifact_snapshot(self.refused_driver)
            refused_integration, exclusions_ri = artifact_snapshot(self.refused_integration)
            observer_audit, exclusions_oa = artifact_snapshot(self.observer_audit)
            baseline, exclusions_b = artifact_snapshot(self.baseline)
            baseline_followup, exclusions_bf = artifact_snapshot(self.baseline_followup)
            baseline_outcome = validate_baseline_observations(baseline, baseline_followup, self.baseline, self.baseline_followup, self.root)
            baseline_runner_raw = read_regular(self.baseline_runner)[0]
            baseline_followup_runner_raw = read_regular(self.baseline_followup_runner)[0]
            native_followup_runner_raw = read_regular(self.native_followup_runner)[0]
            original_native_runner_raw = read_regular(self.original_native_runner)[0]
            publisher_raw = read_regular(Path(__file__).absolute())[0]
            require(sha(publisher_raw) == self.script_hash, 'publisher source changed after invocation')
            observer_runner_raw = read_regular(self.observer_runner)[0]
            observer_controller_raw = read_regular(self.observer_controller)[0]
            require(sha(observer_runner_raw) == OBSERVER_RUNNER_SHA and sha(observer_controller_raw) == OBSERVER_CONTROLLER_SHA,
                    'readonly parser audit original source changed')
            require(sha(baseline_runner_raw) == BASELINE_RUNNER_SHA
                    and sha(baseline_followup_runner_raw) == BASELINE_FOLLOWUP_RUNNER_SHA
                    and sha(native_followup_runner_raw) == FOLLOWUP_SHA
                    and sha(original_native_runner_raw) == ORIGINAL_NATIVE_RUNNER_SHA,
                    'an original native or baseline recorder source changed')
            observations, source_state = validate_observations(controller, native, driver, self.root)
            observations.update(baseline_observation_complete=True, baseline_selected_tests=2,
                                all_baseline_tests_passed=False, baseline_full_library_suite_passed=None,
                                baseline_causal_attribution_established=False)
            c3, c3_tree = observations['binding_child_c3'], observations['binding_child_tree']
            require(gtext(self.root, 'rev-parse', c3 + '^{tree}') == c3_tree and gtext(self.root, 'rev-parse', 'HEAD') == c3,
                    'checkout is not the actual completed C3')
            git(self.root, 'merge-base', '--is-ancestor', C2, c3)
            original_root, followup_root = Path(source_state['native_validation']), Path(source_state['native_followup'])
            for path in (original_root, followup_root):
                directory(path)
                require(not path.is_relative_to(self.root) and not path.is_relative_to(self.out)
                        and not self.out.is_relative_to(path), 'original native output overlaps the checkout or publication receipts')
            original_native, exclusions_o = artifact_snapshot(original_root)
            followup_native, exclusions_f = artifact_snapshot(followup_root)
            native_retention = validate_retained_native(original_native, followup_native, original_root, followup_root, self.root)
            refused_outcome = validate_refused_integration(refused_driver, refused_integration, self.root,
                                                         self.refused_inputs, self.refused_integration, original_root, followup_root)
            require(refused_driver['observed-native-followup-summary.json']['raw'] == followup_native['summary.json']['raw'],
                    'refused driver-02 did not retain the original v4 summary bytes')
            observer_outcome = validate_readonly_observer(observer_audit, self.root, self.observer_controller, original_root, followup_root)
            c3_entries = tree_entries(self.root, c3)
            retained_members = []
            for cohort, origin, files in (('original-v3', original_root, original_native), ('followup-v4', followup_root, followup_native)):
                prefix = NATIVE_PREFIX + '/' + cohort + '/'
                require({path.removeprefix(prefix) for path in c3_entries if path.startswith(prefix)} == set(files),
                        'C3 did not retain every original native observation member: ' + cohort)
                for path, item in sorted(files.items()):
                    target = prefix + path
                    require(git(self.root, 'show', c3 + ':' + target) == item['raw'], 'C3 native evidence bytes differ: ' + target)
                    retained_members.append({'path': target, 'original_source': str(origin / path),
                                             **properties(item['raw'])})
            require(git(self.root, 'show', c3 + ':' + NATIVE_OBSERVATIONS) == controller['native-preflight.json']['raw'],
                    'derived C3 observation differs from the actual controller input review')
            require(followup_native['summary.json']['raw'] == driver['observed-native-followup-summary.json']['raw'],
                    'driver did not preserve the original v4 summary bytes')
            integration_command = strict_json(driver['integrate.command.json']['raw'])
            native_command = strict_json(driver['binding-native.command.json']['raw'])
            native_source = strict_json(native['source.json']['raw'])
            require(integration_command.get('cwd') == native_command.get('cwd') == str(self.root)
                    and integration_command.get('argv') == ['python3', '-B', str(self.inputs / CONTROLLER_PATH),
                        '--phase', 'all', '--root', str(self.root), '--inputs', str(self.inputs),
                        '--native-validation', source_state['native_validation'], '--native-followup', source_state['native_followup'],
                        '--output', str(self.integration)]
                    and native_command.get('argv') == ['python3', '-B', str(self.driver / 'validate_binding_native.py'),
                        '--root', str(self.root), '--integration-output', str(self.integration),
                        '--output', str(self.native), '--target', native_source['explicit_environment']['CARGO_TARGET_DIR']],
                    'gated driver did not execute the recorded roots and original commands')
            require(git(self.root, 'show', BASE + ':' + VERIFY) == git(self.root, 'show', c3 + ':' + VERIFY), 'original source verifier changed')
            native_delta = [p for p in gtext(self.root, 'diff', '--name-only', C2, c3).splitlines()
                            if p.endswith('.rs') or Path(p).name in ('Cargo.toml', 'Cargo.lock')]
            require(native_delta == [INVENTORY], 'C3 native scope differs from its lint-only gate')
            branch = self.current_branch()
            if self.state['phase'] == 'starting':
                require(not git(self.root, 'status', '--porcelain') and not (self.root / PREFIX).exists(), 'initial C3 must be clean and evidence prefix absent')
            references = {label: check_command_references(files) for label, files in (
                ('controller', controller), ('final-native', native), ('driver', driver), ('historical-driver', historical_driver),
                ('refused-driver-02', refused_driver), ('refused-controller-02', refused_integration),
                ('c3-native-original-v3', original_native), ('c3-native-followup-v4', followup_native),
                ('baseline-initial', baseline), ('baseline-followup-02', baseline_followup))}
            driver_path = self.driver_script
            driver_raw = read_regular(driver_path)[0]
            payload = bundle_payload(driver_raw)
            manifest = strict_json(payload[BUNDLE_MANIFEST])
            require(manifest.get('frozen') is True and manifest.get('controller_sha256') == CONTROLLER_SHA
                    and set(payload) == {item['path'] for item in manifest['files']} | {BUNDLE_MANIFEST}, 'original bundle manifest differs')
            for item in manifest['files']:
                require(properties(payload[item['path']])['bytes'] == item['bytes'] and sha(payload[item['path']]) == item['sha256'], 'frozen bundle member differs')
            for path, raw in payload.items():
                require(read_regular(self.inputs / relative(path))[0] == raw, 'provided bundle differs from executed driver: ' + path)
            require(sha(payload[CONTROLLER_PATH]) == CONTROLLER_SHA, 'original controller source missing')
            source_manifest = strict_json(controller['input-manifest.json']['raw'])
            require(source_manifest == source_state['input_sha256'] and source_state['inputs'] == str(self.inputs), 'executed helper input map differs')
            for path, expected in source_manifest.items():
                require(path in payload and sha(payload[path]) == expected, 'executed helper/patch missing: ' + path)
            historical_driver_raw = read_regular(self.historical_driver_script)[0]
            historical_payload = bundle_payload(historical_driver_raw, historical=True)
            historical_manifest = strict_json(historical_payload[HISTORICAL_MANIFEST])
            require(historical_manifest.get('frozen') is True
                    and historical_manifest.get('controller_sha256') == HISTORICAL_CONTROLLER_SHA
                    and set(historical_payload) == {item['path'] for item in historical_manifest['files']} | {HISTORICAL_MANIFEST},
                    'historical frozen manifest differs')
            for item in historical_manifest['files']:
                raw = historical_payload[item['path']]
                require(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'historical frozen member differs')
            for path, raw in historical_payload.items():
                require(read_regular(self.historical_inputs / relative(path))[0] == raw, 'historical input changed: ' + path)
            require(sha(historical_payload['integration/integrate_candidate.py']) == HISTORICAL_CONTROLLER_SHA,
                    'historical controller source missing')
            refused_driver_raw = read_regular(self.refused_driver_script)[0]
            refused_payload = bundle_payload(refused_driver_raw, refused=True)
            refused_manifest = strict_json(refused_payload[REFUSED_MANIFEST])
            require(refused_manifest.get('frozen') is True and refused_manifest.get('controller_sha256') == REFUSED_CONTROLLER_SHA
                    and set(refused_payload) == {item['path'] for item in refused_manifest['files']} | {REFUSED_MANIFEST},
                    'refused attempt-02 manifest differs')
            for item in refused_manifest['files']:
                raw = refused_payload[item['path']]
                require(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'refused attempt-02 member differs')
            for path, raw in refused_payload.items():
                require(read_regular(self.refused_inputs / relative(path))[0] == raw, 'refused attempt-02 input changed: ' + path)
            require(sha(refused_payload[REFUSED_CONTROLLER_PATH]) == REFUSED_CONTROLLER_SHA,
                    'refused attempt-02 controller source missing')
            raw_files, members = {}, []
            def add(name, raw, origin, original_mode='unknown'):
                name = relative(name)
                if name.endswith('.md'):
                    name += '.txt'
                destination = PREFIX + '/' + name
                require(destination not in raw_files, 'archive filename collision: ' + destination)
                raw_files[destination] = raw
                members.append({'path': name, 'original_source': origin, 'original_mode': original_mode, **properties(raw)})
            for label, root, files in (('controller', self.integration, controller), ('final-native', self.native, native),
                                      ('driver', self.driver, driver), ('historical-orchestration/driver-output', self.historical_driver, historical_driver),
                                      ('historical-orchestration/attempt-02/driver-output', self.refused_driver, refused_driver),
                                      ('historical-orchestration/attempt-02/controller-output', self.refused_integration, refused_integration),
                                      ('observer-audit-03', self.observer_audit, observer_audit),
                                      ('baseline-controls/initial', self.baseline, baseline),
                                      ('baseline-controls/followup-02', self.baseline_followup, baseline_followup)):
                for path, item in sorted(files.items()):
                    add(label + '/' + path, item['raw'], str(root / path), item['original_mode'])
            for path, raw in sorted(payload.items()):
                add('orchestration/current/' + path, raw, str(self.inputs / path))
            for path, raw in sorted(historical_payload.items()):
                add('historical-orchestration/bundle-members/' + path, raw, str(self.historical_inputs / path))
            for path, raw in sorted(refused_payload.items()):
                add('historical-orchestration/attempt-02/bundle-members/' + path, raw, str(self.refused_inputs / path))
            add('orchestration/current/remote_integration_driver_03.py', driver_raw, str(driver_path))
            add('historical-orchestration/remote_integration_driver_01.py', historical_driver_raw, str(self.historical_driver_script))
            add('historical-orchestration/attempt-02/remote_integration_driver_02.py', refused_driver_raw, str(self.refused_driver_script))
            add('historical-orchestration/run_native_validation_v3.py', original_native_runner_raw, str(self.original_native_runner))
            add('baseline-controls/orchestration/run_baseline_two_controls.py', baseline_runner_raw, str(self.baseline_runner))
            add('baseline-controls/orchestration/run_baseline_two_controls_v2.py', baseline_followup_runner_raw, str(self.baseline_followup_runner))
            add('orchestration/current/run_native_followup_v4.py', native_followup_runner_raw, str(self.native_followup_runner))
            add('orchestration/observer-audit-03/run_native_observer_audit_v3.py', observer_runner_raw, str(self.observer_runner))
            add('orchestration/observer-audit-03/integrate_candidate_v3_observer.py', observer_controller_raw, str(self.observer_controller))
            add('orchestration/current/publish_followthrough_receipts_v2.py', publisher_raw, str(Path(__file__).absolute()))
            excluded = {'controller': exclusions_c, 'final-native': exclusions_n, 'driver': exclusions_d,
                        'historical-driver': exclusions_h, 'c3-native-original-v3': exclusions_o, 'c3-native-followup-v4': exclusions_f,
                        'refused-driver-02': exclusions_rd, 'refused-controller-02': exclusions_ri,
                        'observer-audit-03': exclusions_oa,
                        'baseline-initial': exclusions_b, 'baseline-followup-02': exclusions_bf}
            sources = dict(observations, schema='pon-followthrough-final-integration-sources-v2',
                evidence_commit_scope='only-new-files-under-' + PREFIX,
                c4_reexecutes_c2_or_c3=False, c4_identity_recorded_after_commit=True,
                controller_sha256=CONTROLLER_SHA, native_recorder_sha256=NATIVE_SHA, driver_sha256=DRIVER_SHA,
                publisher_sha256=self.script_hash, original_native_recorder_sha256=ORIGINAL_NATIVE_RUNNER_SHA,
                original_command_reference_closure=references, exclusions=excluded,
                selected_history=self.history, retained_native=native_retention, retained_native_members=retained_members,
                historical_orchestration=historical_outcome, refused_integration_02=refused_outcome,
                readonly_native_parser_audit=observer_outcome,
                baseline_selected_controls=baseline_outcome,
                compressed_archive_retention='Exact original archive bytes remain encoded in each pinned driver source; no executable or standalone archive copied')
            raw_files[PREFIX + '/sources.json'] = encoded(sources)
            readme = f'''# Final integration and retained failed native observations

Status: **draft review only; the C2 full node suite failed; security HOLD**.

This evidence-only child retains actual C3 integration and native-lint checks,
both original C2 observation sets, independent baseline controls, and both old
driver refusals. Every pre-existing C3 Git blob and mode remains unchanged. The
C4 commit identity is recorded by the publication recorder after it exists.

## Distinct execution scopes

* **C2 `{C2}`**, tree `{C2_TREE}`: the original full node library run exited
  **101**, with **1,285 passed, 2 failed and 39 original ignored**. Its
  [original stdout](../native/original-v3/node-library-v3.stdout.log) and
  [complete command history](../native/original-v3/commands.json) retain that
  failure. No v3 completion summary or v3 source-after receipt is manufactured.
  The subsequent [v4 summary](../native/followup-v4/summary.json) records two
  separately selected tests that still exited 101. The other twelve v4 commands
  exited 0, including the 3 release example tests, unchanged three-owner strict
  Clippy, format check, release build, 64 actual fresh-probe samples, independent
  reader and 26 reader controls. The v4 before/after source bytes also match the
  original v3 before record. Observation completion is true; full-suite success
  is false. Earlier C1 failures and the limited corrected-node counterfactual
  retain their own original scope.
* **Exact baseline `{BASE}`**: the [initial recorder refusal](baseline-controls/initial/failure.json)
  happened before tests because the orchestration guard rejected global shallow
  history. The independent [followup](baseline-controls/followup-02/summary.json)
  observed only two unchanged exact tests: the large-parent test passed and the
  inactive-page test failed with `PUBLIC_MUTATION_CPU_BUDGET`. Its full library
  suite was not executed, so `full_library_suite_passed` remains null. This is
  not the `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH` diagnostic failure that concealed
  the original C2 full run's final-page result. These observations do not establish
  identical causes, host-only causality or absence of a regression, and are not
  counted as C2 executions.
* **C3 `{c3}`**, tree `{c3_tree}`: the [controller summary](controller/summary.json),
  [command records](controller/commands.json), [native-lint summary](final-native/summary.json)
  and [driver-03 summary](driver/summary.json) retain actual source-bracketed checks.
  Every planned C3 integration check and the unchanged six-command native child
  gate passed. The only Rust/Cargo delta from C2 is the generated distributed
  source inventory. The child reran locked metadata and the original three-owner
  `--all-targets -- -D warnings` Clippy command; it did not repeat or inherit a
  passing full native suite.
* **C4** adds this directory only. Its own source-identity and repository/Markdown
  checks have separate receipts. They do not rerun or upgrade any earlier test.

## Complete original evidence

[members.json](members.json) records each copied original byte count, SHA-256,
Git blob and source location. [sources.json](sources.json) also records every
C3-retained original-v3/followup-v4 member, command-stream closure, explicit
index/lock exclusions and the selected Git lineage. Global history may be
shallow; complete global history is not claimed. The selected real commit/tree
and parent path remain mandatory, and no Git fetch or history rewrite is used.

Current frozen scripts and bundle members are under `orchestration/current/`.
The original driver-01 failure, its fourteen frozen bundle members, unchanged
driver source and original v3 native recorder are independently retained under
`historical-orchestration/`.
The failed second attempt is separate under `historical-orchestration/attempt-02/`:
its controller refused the full-run test-count parser before creating C3, and
the driver recorded the actual exit 2. Its complete original outputs, fourteen
frozen bundle members, manifest and driver source remain unchanged.
The separate `observer-audit-03/` records a read-only parser check of the original
39 commands plus the 14 followup commands and their 121 raw members. Its exact
runner and imported controller are under `orchestration/observer-audit-03/`.
It executed no native tests, changed no project source and created no C3; its
parser success is not integration or native-suite success.
Each compressed archive's exact original bytes remain encoded in its pinned
driver source. Both baseline output sets and both original baseline recorders
are under `baseline-controls/`. Raw bytes are never trimmed or rewritten;
historical Markdown is archived as `.md.txt` to preserve bytes without creating
new relative navigation links. No native executable, Cargo target or Git
index/lock is copied.

The 138-input QROM mapping and source/CI controls remain finite observations.
They establish no QROM reduction, cheapest legal work cost, public-prefix,
chain-growth or chain-quality bound, confirmation-failure probability or
production qualification. All qualifications remain **HOLD/false/null**.
Hosted GitHub Actions completion is not asserted.
'''
            raw_files[PREFIX + '/README.md'] = readme.encode()
            raw_files[PREFIX + '/members.json'] = encoded({'schema': 'pon-followthrough-final-integration-members-v2',
                'code_checkpoint_c2': C2, 'binding_child_c3': c3, 'binding_child_tree': c3_tree,
                'copied_members': members, 'copied_count': len(members), 'copied_bytes': sum(item['bytes'] for item in members),
                'generated_members': [{'path': name.removeprefix(PREFIX + '/'), **properties(raw_files[name])}
                                      for name in (PREFIX + '/sources.json', PREFIX + '/README.md')],
                'manifest_identity': 'verified by the actual staged/committed Git tree; no self-hash asserted',
                'existing_c3_files_modified': False, 'open_consensus_qualified': False, 'production_activation': False})
            expected = {path: properties(raw) for path, raw in raw_files.items()}
            require(sum(len(raw) for raw in raw_files.values()) <= MAX_TOTAL, 'complete evidence collection exceeds bound')
            if self.state['phase'] == 'preparing':
                require(self.state['expected_files'] == expected and self.state['c3'] == c3 and self.state['branch'] == branch,
                        'prepare resume source observations changed; inspect original state')
            else:
                self.state.update(phase='preparing', c3=c3, c3_tree=c3_tree, branch=branch, expected_head=c3,
                                  expected_files=expected, observations=observations)
                self.save()
            self.working_guard(allow_partial=True)
            self.run('prepare-preflight', ['bash', 'scripts/project-preflight.sh'])
            for path, raw in raw_files.items():
                target = self.root / path
                if target.exists():
                    require(read_regular(target)[0] == raw, 'partial evidence copy differs: ' + path)
                else:
                    write_new(target, raw)
            for root, original in ((self.integration, controller), (self.native, native), (self.driver, driver),
                                   (self.historical_driver, historical_driver), (original_root, original_native), (followup_root, followup_native),
                                   (self.refused_driver, refused_driver), (self.refused_integration, refused_integration),
                                   (self.observer_audit, observer_audit),
                                   (self.baseline, baseline), (self.baseline_followup, baseline_followup)):
                latest, _ = artifact_snapshot(root)
                require(snapshot_identity(latest) == snapshot_identity(original), 'original output changed during copying: ' + str(root))
            for path, raw in payload.items():
                require(read_regular(self.inputs / path)[0] == raw, 'frozen input changed during copying')
            for path, raw in historical_payload.items():
                require(read_regular(self.historical_inputs / path)[0] == raw, 'historical frozen input changed during copying')
            for path, raw in refused_payload.items():
                require(read_regular(self.refused_inputs / path)[0] == raw, 'refused attempt-02 input changed during copying')
            require(read_regular(self.driver_script)[0] == driver_raw
                    and read_regular(self.historical_driver_script)[0] == historical_driver_raw
                    and read_regular(self.refused_driver_script)[0] == refused_driver_raw
                    and read_regular(self.baseline_runner)[0] == baseline_runner_raw
                    and read_regular(self.baseline_followup_runner)[0] == baseline_followup_runner_raw
                    and read_regular(self.native_followup_runner)[0] == native_followup_runner_raw
                    and read_regular(self.original_native_runner)[0] == original_native_runner_raw
                    and read_regular(self.observer_runner)[0] == observer_runner_raw
                    and read_regular(self.observer_controller)[0] == observer_controller_raw
                    and read_regular(Path(__file__).absolute())[0] == publisher_raw,
                    'a pinned orchestration source changed during copying')
            self.working_guard()
            paths = sorted(expected)
            for offset in range(0, len(paths), 100):
                self.run('stage-explicit-raw-evidence', ['git', 'add', '-f', '--', *paths[offset:offset + 100]])
            staged = gtext(self.root, 'write-tree')
            self.verify_tree(staged)
            require(not git(self.root, 'diff', '--name-only'), 'unstaged changes remain after exact evidence staging')
            self.state.update(phase='prepared', prepared_tree=staged)
            self.save(); self.status('prepare', 'finished', 0)
        finally:
            os.close(lock)

    def adopt_commit(self):
        head = gtext(self.root, 'rev-parse', 'HEAD')
        require(gtext(self.root, 'rev-list', '--parents', '-n', '1', head).split() == [head, self.state['c3']]
                and gtext(self.root, 'rev-parse', head + '^{tree}') == self.state['prepared_tree']
                and gtext(self.root, 'log', '-1', '--format=%s', head) == COMMIT_MESSAGE, 'pending commit cannot be reconciled')
        self.verify_tree(head)
        require(not git(self.root, 'status', '--porcelain'), 'C4 is not clean after commit')
        self.state.update(phase='committed', c4=head, expected_head=head, pending_write=None)
        self.save()

    def commit(self):
        require(self.state['phase'] in ('prepared', 'committing'), 'commit requires exact prepared evidence')
        if self.state['phase'] == 'committing' and gtext(self.root, 'rev-parse', 'HEAD') != self.state['c3']:
            self.adopt_commit(); self.status('commit-reconciled', 'finished', 0); return
        self.working_guard()
        require(gtext(self.root, 'write-tree') == self.state['prepared_tree'], 'prepared evidence index changed')
        self.verify_tree(self.state['prepared_tree'])
        self.run('commit-preflight', ['bash', 'scripts/project-preflight.sh'])
        self.working_guard()
        self.state.update(phase='committing', pending_write={'kind': 'local-commit', 'parent': self.state['c3'], 'tree': self.state['prepared_tree']})
        self.save()
        self.run('commit-evidence-only-child', ['git', 'commit', '-m', COMMIT_MESSAGE])
        self.adopt_commit(); self.status('commit', 'finished', 0)

    def validate(self):
        require(self.state['phase'] in ('committed', 'validation_failed', 'validated'), 'validation requires actual C4')
        self.working_guard(); self.verify_tree(self.state['c4'])
        require(not git(self.root, 'status', '--porcelain'), 'C4 validation requires clean worktree')
        require(git(self.root, 'show', BASE + ':' + VERIFY) == read_regular(self.root / VERIFY)[0], 'original source verifier changed')
        attempt = len(self.state.get('validation_runs', [])) + 1
        prefix = f'c4-validation-{attempt:02d}'
        before, after = self.out / (prefix + '-before.json'), self.out / (prefix + '-after.json')
        first = len(self.commands)
        source = [sys.executable, '-B', VERIFY, '--kind', 'head', '--expected-head', self.state['c4'], '--output']
        for label, argv in (
            ('preflight', ['bash', 'scripts/project-preflight.sh']),
            ('source-before', source + [str(before)]),
            ('repository-and-markdown', [sys.executable, '-B', 'scripts/ci/check_repository.py']),
            ('generated-metadata-whitespace', ['git', 'diff', '--check', self.state['c3'], self.state['c4'], '--',
                PREFIX + '/README.md', PREFIX + '/members.json', PREFIX + '/sources.json']),
            ('source-after', source + [str(after)]),
            ('source-identical', ['cmp', str(before), str(after)]),
        ):
            self.working_guard()
            self.run(prefix + '-' + label, argv, required=False)
        rows = self.commands[first:]
        success = all(row['exit_code'] == 0 for row in rows)
        if success:
            bracket = {path.name: {'raw': read_regular(path)[0]} for path in (before, after)}
            original_bracket(bracket, before.name, after.name, self.state['c4'], self.state['prepared_tree'])
        self.working_guard(); self.verify_tree(self.state['c4'])
        require(not git(self.root, 'status', '--porcelain'), 'validation modified C4')
        result = {'schema': 'pon-followthrough-evidence-child-checks-v2', 'complete': success,
            'code_checkpoint_c2': C2, 'binding_child_c3': self.state['c3'], 'evidence_child_c4': self.state['c4'],
            'c4_tree': self.state['prepared_tree'], 'all_existing_c3_blobs_and_modes_unchanged': True,
            'only_added_prefix': PREFIX, 'copied_raw_bytes_unchanged': True,
            'native_tests_reexecuted': False, 'hosted_ci_observed_complete': False,
            'native_observation_complete': True, 'native_full_suite_passed': False, 'draft_only': True,
            'all_baseline_tests_passed': False, 'baseline_full_library_suite_passed': None,
            'open_consensus_qualified': False, 'production_activation': False,
            'commands': [{'label': row['label'], 'exit_code': row['exit_code']} for row in rows], 'security_status': 'HOLD'}
        write_new(self.out / (prefix + '-summary.json'), encoded(result))
        self.state.setdefault('validation_runs', []).append({'path': prefix + '-summary.json', 'complete': success})
        self.state['phase'] = 'validated' if success else 'validation_failed'
        self.save(); self.status('validate', 'finished' if success else 'failed', 0 if success else 2)
        require(success, 'C4 identity/repository check failed; no publication attempted')

    def github_identity(self):
        value = self.output_json(self.run('github-user', ['gh', 'api', 'user']))
        require(value.get('login') == ACCOUNT, 'GitHub write identity is not ProfHepta')

    def push_origin(self):
        origin = gtext(self.root, 'remote', 'get-url', '--push', 'origin')
        require(origin in (f'https://github.com/{REPOSITORY}.git', f'https://github.com/{REPOSITORY}',
            f'git@github.com:{REPOSITORY}.git'), 'origin is not the reviewed canonical repository')
        return origin

    def remote_tip(self):
        origin = self.push_origin()
        # Read the exact checked push target; a distinct fetch URL on the same
        # remote name must never supply confirmation of this write's outcome.
        row = self.run('remote-branch-read', ['git', 'ls-remote', '--heads', origin, 'refs/heads/' + self.state['branch']])
        lines = read_regular(self.out / row['stdout']['file'])[0].decode().splitlines()
        require(len(lines) <= 1, 'remote branch lookup is ambiguous')
        if not lines:
            return None
        oid, ref = lines[0].split()
        require(re.fullmatch('[0-9a-f]{40}', oid) and ref == 'refs/heads/' + self.state['branch'], 'remote ref identity differs')
        return oid

    def observe_base(self):
        row = self.run('draft-base-read', ['git', 'ls-remote', '--heads', self.push_origin(), 'refs/heads/' + PR_BASE])
        lines = read_regular(self.out / row['stdout']['file'])[0].decode().splitlines()
        require(len(lines) == 1, 'draft base lookup is absent or ambiguous')
        oid, ref = lines[0].split()
        require(re.fullmatch('[0-9a-f]{40}', oid) and ref == 'refs/heads/' + PR_BASE, 'draft base ref identity differs')
        comparison_row = self.run('draft-base-comparison', ['gh', 'api', '--method', 'GET',
            f'repos/{REPOSITORY}/compare/{BASE}...{oid}'])
        comparison = self.output_json(comparison_row)
        require(comparison.get('base_commit', {}).get('sha') == BASE
                and comparison.get('status') in ('ahead', 'behind', 'diverged', 'identical')
                and type(comparison.get('ahead_by')) is int and comparison['ahead_by'] >= 0
                and type(comparison.get('behind_by')) is int and comparison['behind_by'] >= 0,
                'draft base comparison identity or counters are unavailable')
        observation = {'ref': PR_BASE, 'head': oid, 'command': row['label'], 'observed_unix_ns': row['end_unix_ns'],
                       'selected_baseline': BASE, 'differs_from_selected_baseline': oid != BASE,
                       'comparison_command': comparison_row['label'], 'base_relationship': comparison['status'],
                       'ahead_by': comparison['ahead_by'], 'behind_by': comparison['behind_by'],
                       'base_advanced_since_source_checkpoint': comparison['ahead_by'] > 0,
                       'merge_result_verified': False, 'moved_base_tests_inherited': False}
        self.state.setdefault('base_observations', []).append(observation)
        self.save()
        return observation

    def find_pr(self):
        found = []
        for page in range(1, 11):
            values = self.output_json(self.run('existing-pr-read', ['gh', 'api', '--method', 'GET', f'repos/{REPOSITORY}/pulls',
                '-f', 'state=all', '-f', f'head={OWNER}:{self.state["branch"]}',
                '-f', 'per_page=100', '-f', 'page=' + str(page)]))
            require(type(values) is list, 'PR lookup was not an array')
            for value in values:
                if value.get('head', {}).get('ref') == self.state['branch'] and value.get('head', {}).get('repo', {}).get('full_name') == REPOSITORY:
                    found.append(value)
            if len(values) < 100:
                break
        else:
            raise Refusal('PR lookup pagination bound exceeded; no write performed')
        require(len(found) <= 1, 'multiple historical PRs use this head; review required before a write')
        if found:
            value = found[0]
            require(value.get('state') == 'open' and value.get('draft') is True
                    and value.get('base', {}).get('ref') == PR_BASE and value.get('user', {}).get('login') == ACCOUNT,
                    'existing same-head PR is not the expected open ProfHepta draft')
            return value
        return None

    def pr_body(self):
        c3, c4 = self.state['c3'], self.state['c4']
        base_observation = self.state['publication_base_observation']
        require(base_observation.get('ref') == PR_BASE
                and re.fullmatch('[0-9a-f]{40}', base_observation.get('head', ''))
                and base_observation.get('merge_result_verified') is False
                and base_observation.get('moved_base_tests_inherited') is False,
                'publication base observation missing or upgraded')
        observed_base_head = base_observation['head']
        require(type(base_observation.get('base_advanced_since_source_checkpoint')) is bool,
                'publication base advancement observation missing')
        base_advanced = str(base_observation['base_advanced_since_source_checkpoint']).lower()
        return f'''{MARKER}
## Draft status and remaining failures

This candidate remains **HOLD**. C2's full node suite exited **101**: **1,285
passed, 2 failed, 39 original ignored**. Its two original exact reruns also
exited 101. This draft preserves those failures; native observation completion
is true and native full-suite success is false. No project CI, CPU budget,
deadline, original test assertion or qualification flag is relaxed.

## Changes

Native payment/effect reobservation now rechecks its persistent journal after
callbacks. Confirmation observation checks retained chainwork and its genesis
anchor, then fences the final storage epoch. The branch also registers the
native evidence controls, repairs CI evidence collection and binds selected
research inputs to the actual code checkpoint. Unknown and owner-stop semantics
remain required.

## Source-specific observations

- **C2 `{C2}`** retains the original failed full suite, earlier red/green controls
  and their precise counterfactual limits. Its independent v4 followup has
  fourteen commands: two exact test failures and twelve zero exits. The latter
  include 3 release example tests, unchanged three-owner strict Clippy, format,
  release build, 64 actual fresh-probe samples, its reader and 26 reader tests.
  The v4 source bracket matches the original v3 before record. No missing v3
  summary or source-after receipt was invented.
- **Baseline `{BASE}`** retains an initial shallow-history orchestration refusal
  before tests, followed by two unchanged selected controls: large-parent passed;
  inactive-page failed with `PUBLIC_MUTATION_CPU_BUDGET`. Only two tests were
  run, so full-library success remains null. This error is distinct from C2's
  full-run `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH` diagnostic failure. The controls
  establish neither a shared cause nor absence of a regression.
- **C3 `{c3}`** has actual source/corpus/ledger/CI-contract/repository/format and
  QROM mapping checks, each with zero exit. The only Rust/Cargo delta from C2 is
  the generated distributed inventory. The separate child gate reruns locked
  metadata and the unchanged three-owner `--all-targets -- -D warnings` Clippy
  command. These checks do not confer full-suite success on C3.
- **C4 `{c4}`** adds original receipts only under `{PREFIX}/`. Every existing C3
  Git blob and mode is identical. Its own source and repository/Markdown checks
  are separately recorded; they do not rerun C2 or C3 tests.

## Moving base and merge scope

The publication recorder observed base ref `{PR_BASE}` at
`{observed_base_head}`. This is a separately recorded remote-ref observation;
the selected implementation lineage remains based on `{BASE}`. The base can
advance independently. This candidate has not merged or rebased onto that
observed base head, and its merge result against that head has not been
validated. No tests or CI results from the moved base or PR #847 are inherited
by the C2/C3/C4 evidence above.

`base_advanced_since_source_checkpoint={base_advanced}`;
`merge_result_verified=false`; `moved_base_tests_inherited=false`.

[Complete final integration receipts](https://github.com/{REPOSITORY}/blob/{c4}/{PREFIX}/README.md)
retain all controller/native-lint/driver outputs, both baseline output sets,
both failed historical driver attempts, the second attempt's exact controller
preflight refusal, and all three frozen orchestration bundles. Manifests
record original bytes, SHA-256 and Git blob IDs, including ignored logs added
by explicit paths. Global shallow history is disclosed; selected source objects,
parent edges and complete materialized source checks remain mandatory.

This is a draft for review. Hosted GitHub Actions completion is not asserted.
QROM soundness, cheapest legal work cost, public consensus bounds and production
admission remain unproved or disabled. Qualification remains **HOLD/false/null**.
'''

    def finish_pr(self, value, body):
        require(value is not None and value.get('draft') is True and value.get('state') == 'open'
                and value.get('head', {}).get('sha') == self.state['c4']
                and value.get('base', {}).get('ref') == PR_BASE
                and re.fullmatch('[0-9a-f]{40}', value.get('base', {}).get('sha', ''))
                and value.get('title') == TITLE and value.get('body') == body,
                'draft PR state differs from the concrete publication payload')
        self.state.update(phase='published', pending_write=None, pull_request={'number': value['number'], 'url': value['html_url'],
                          'draft': True, 'head': self.state['c4'], 'base': PR_BASE,
                          'observed_pr_base_head': value['base']['sha'], 'merge_result_verified': False,
                          'moved_base_tests_inherited': False})
        self.save(); self.status('publish', 'finished', 0)

    def publish(self):
        require(self.state['phase'] in ('validated', 'pushed', 'publication_unknown', 'published'), 'publish requires actual completed C4 checks')
        require(self.state.get('validation_runs') and self.state['validation_runs'][-1]['complete'] is True, 'C4 checks incomplete')
        failed_native_draft_scope(self.state.get('observations', {}))
        require(self.state['observations'].get('baseline_observation_complete') is True
                and self.state['observations'].get('baseline_selected_tests') == 2
                and self.state['observations'].get('all_baseline_tests_passed') is False
                and 'baseline_full_library_suite_passed' in self.state['observations']
                and self.state['observations']['baseline_full_library_suite_passed'] is None,
                'independent baseline evidence is incomplete or upgraded')
        self.working_guard(); self.verify_tree(self.state['c4'])
        require(not git(self.root, 'status', '--porcelain'), 'publication checkout is not clean')
        self.run('publish-preflight', ['bash', 'scripts/project-preflight.sh'])
        self.github_identity()
        observed_base = self.observe_base()
        if 'publication_base_observation' not in self.state:
            require(self.state['phase'] == 'validated' and self.state.get('pending_write') is None,
                    'a pending publication lost its original base observation')
            self.state['publication_base_observation'] = observed_base
            self.save()
        body = self.pr_body()
        existing = self.find_pr()
        if self.state['phase'] == 'published':
            self.finish_pr(existing, body)
            return
        pending = self.state.get('pending_write')
        if pending and pending['kind'] in ('create-pr', 'update-pr'):
            require(pending['body_sha256'] == sha(body.encode()), 'pending PR payload changed')
            self.finish_pr(existing, body)
            return
        remote = self.remote_tip()
        if pending:
            require(pending['kind'] == 'push' and remote == self.state['c4'],
                    'previous GitHub write has no confirmed success; retain this output and do not blindly replay under another key')
            self.state.update(phase='pushed', pending_write=None); self.save()
        elif remote != self.state['c4']:
            require(self.state['phase'] == 'validated', 'previously pushed branch moved; no blind repush')
            if remote is not None:
                git(self.root, 'cat-file', '-e', remote + '^{commit}')
                git(self.root, 'merge-base', '--is-ancestor', remote, self.state['c4'])
            self.working_guard()
            # Source of the actual refspec is the exact C4 SHA, not mutable HEAD.
            # This is the same four-field update grammar consumed by pre-push.
            update = f'{self.state["c4"]} {self.state["c4"]} refs/heads/{self.state["branch"]} {remote or "0" * 40}\n'.encode()
            self.run('exact-push-preflight', ['bash', 'scripts/project-preflight.sh', '--push', 'origin', self.push_origin()],
                     input_bytes=update)
            self.state.update(phase='publication_unknown', pending_write={'kind': 'push', 'expected_head': self.state['c4'], 'prior_remote': remote})
            self.save()
            self.working_guard()
            self.run('normal-fast-forward-push', ['git', 'push', 'origin', self.state['c4'] + ':refs/heads/' + self.state['branch']], required=False)
            require(self.remote_tip() == self.state['c4'], 'push outcome unconfirmed; no automatic replay')
            self.state.update(phase='pushed', pending_write=None); self.save()
        else:
            self.state.update(phase='pushed', pending_write=None); self.save()
        self.working_guard()
        existing = self.find_pr()
        if (existing is not None and existing.get('head', {}).get('sha') == self.state['c4']
                and existing.get('title') == TITLE and existing.get('body') == body):
            self.finish_pr(existing, body)
            return
        require(existing is None or existing.get('head', {}).get('sha') == self.state['c4'], 'existing draft head did not observe pushed C4')
        payload = {'title': TITLE, 'body': body}
        if existing is None:
            payload.update(head=self.state['branch'], base=PR_BASE, draft=True, maintainer_can_modify=True)
            kind, endpoint, method = 'create-pr', f'repos/{REPOSITORY}/pulls', 'POST'
        else:
            kind, endpoint, method = 'update-pr', f'repos/{REPOSITORY}/pulls/{existing["number"]}', 'PATCH'
        payload_path = self.out / ('pull-request-' + str(len(self.commands) + 1) + '.json')
        write_new(payload_path, encoded(payload))
        write_new(payload_path.with_suffix('.body.txt'), body.encode())
        self.github_identity()
        self.run('api-write-preflight', ['bash', 'scripts/project-preflight.sh'])
        self.working_guard()
        require(self.remote_tip() == self.state['c4'], 'published branch moved before the PR write')
        self.state.update(phase='publication_unknown', pending_write={'kind': kind, 'endpoint': endpoint,
            'payload': payload_path.name, 'payload_sha256': sha(encoded(payload)), 'body_sha256': sha(body.encode())})
        self.save()
        self.run('rest-draft-pull-request', ['gh', 'api', '--method', method, endpoint, '--input', str(payload_path)], required=False)
        self.finish_pr(self.find_pr(), body)

    def summary(self):
        result = {'schema': 'pon-followthrough-publication-summary-v2', 'phase': self.state['phase'],
            'local_evidence_complete': self.state.get('validation_runs', [{}])[-1].get('complete', False),
            'published': self.state['phase'] == 'published', 'code_checkpoint_c2': C2,
            'binding_child_c3': self.state.get('c3'), 'evidence_child_c4': self.state.get('c4'),
            'draft_pull_request': self.state.get('pull_request'), 'pending_write': self.state.get('pending_write'),
            'publication_base_observation': self.state.get('publication_base_observation'),
            'latest_base_observation': self.state.get('base_observations', [None])[-1],
            'base_advanced_since_source_checkpoint': self.state.get('publication_base_observation', {}).get('base_advanced_since_source_checkpoint'),
            'merge_result_verified': False, 'moved_base_tests_inherited': False,
            'evidence_member_count': len(self.state['expected_files']), 'commands_recorded': len(self.commands),
            'native_observation_complete': self.state.get('observations', {}).get('native_observation_complete', False),
            'native_full_suite_passed': False, 'draft_only': True,
            'baseline_observation_complete': self.state.get('observations', {}).get('baseline_observation_complete', False),
            'all_baseline_tests_passed': self.state.get('observations', {}).get('all_baseline_tests_passed'),
            'baseline_full_library_suite_passed': None,
            'hosted_ci_observed_complete': False, 'open_consensus_qualified': False,
            'production_activation': False, 'security_status': 'HOLD'}
        atomic_json(self.out / 'summary.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('prepare', 'commit', 'validate', 'publish', 'all-local'), required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--integration-output', type=Path, required=True)
    parser.add_argument('--final-native-output', type=Path, required=True)
    parser.add_argument('--driver-output', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True, help='actual extracted integration-bundle-03 directory')
    parser.add_argument('--driver-script', type=Path, help='frozen remote_integration_driver_03.py; default is the bundle parent')
    parser.add_argument('--historical-driver-output', type=Path, required=True, help='unchanged failed integration-driver-01 output')
    parser.add_argument('--historical-inputs', type=Path, required=True, help='unchanged extracted integration-bundle-01 directory')
    parser.add_argument('--historical-driver-script', type=Path, help='original remote_integration_driver_01.py; default is the old bundle parent')
    parser.add_argument('--refused-driver-output', type=Path, required=True, help='unchanged failed integration-driver-02 output')
    parser.add_argument('--refused-integration-output', type=Path, required=True, help='unchanged integration-02 preflight refusal output')
    parser.add_argument('--refused-inputs', type=Path, required=True, help='unchanged extracted integration-bundle-02 directory')
    parser.add_argument('--refused-driver-script', type=Path, help='original remote_integration_driver_02.py; default is the refused bundle parent')
    parser.add_argument('--baseline-output', type=Path, required=True, help='original shallow-guard refusal output; no tests executed')
    parser.add_argument('--baseline-followup-output', type=Path, required=True, help='original exact-baseline two-test output-02')
    parser.add_argument('--baseline-runner', type=Path, required=True, help='original pinned baseline recorder source')
    parser.add_argument('--baseline-followup-runner', type=Path, required=True, help='original pinned baseline v2 recorder source')
    parser.add_argument('--native-followup-runner', type=Path, help='original run_native_followup_v4.py; default is the bundle parent')
    parser.add_argument('--original-native-runner', type=Path, help='original run_native_validation_v3.py; default is the bundle parent')
    parser.add_argument('--observer-audit-output', type=Path, help='original readonly native-observer-audit-03 output; default is the bundle parent')
    parser.add_argument('--observer-audit-runner', type=Path, help='original run_native_observer_audit_v3.py; default is the bundle parent')
    parser.add_argument('--observer-audit-controller', type=Path, help='original imported integrate_candidate_v3_observer.py; default is the bundle parent')
    parser.add_argument('--output', type=Path, required=True, help='one stable external publication receipt directory for all phases')
    args = parser.parse_args()
    owner = None
    try:
        owner = Publisher.__new__(Publisher)
        owner.__init__(args)
        if args.phase in ('prepare', 'all-local'):
            owner.prepare()
        if args.phase in ('commit', 'all-local'):
            owner.commit()
        if args.phase in ('validate', 'all-local'):
            owner.validate()
        if args.phase == 'publish':
            owner.publish()
        print(json.dumps(owner.summary(), sort_keys=True), flush=True)
        return 0
    except (Refusal, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        failure = {'status': 'REFUSE_OR_ACTUAL_FAILURE', 'reason': str(error), 'requested_phase': args.phase,
                   'recorded_unix_ns': time.time_ns(), 'automatic_rollback_performed': False,
                   'blind_remote_replay_authorized': False, 'production_activation': False, 'security_status': 'HOLD'}
        if owner is not None and getattr(owner, 'owns_output', False):
            write_new(owner.out / ('failure-' + str(failure['recorded_unix_ns']) + '.json'), encoded(failure))
            atomic_json(owner.out / 'failure.json', failure)
            owner.status(args.phase, 'failed', 2)
            owner.summary()
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
