#!/usr/bin/env python3
"""Review/apply the one-file C2 successor of the retained 189b9b5 QROM V2 map.

External integration recorder. Default: review only. --apply preserves original
V2 inputs and their actual refusal, updates four selected binding files, executes
the complete 138-input mapping and its unchanged fourteen named controls, and
creates independent evidence. No Cargo, remote operation, commit, or activation.
"""
# Independent orchestration v2: the selected lineage is complete even when
# unrelated global history is shallow. The original v1 recorder is retained.
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import uuid

BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
SELECTED_C1 = "11c9562252d3cf56b423c7756569be0c669d9606"
SELECTED_C2 = "8d8c0e64e7a301fc111a6720721a14816639e5aa"
SELECTED_LINEAGE = (
    (BASE, "00479a98dabc6b1fd91a0ceef82ffbdbffb78067", None),
    (SELECTED_C1, "94e1b4f1718dec1b88bccd7e1996ba83ca29ff8a", BASE),
    (SELECTED_C2, "7c003a3d183ad33ff4f3349cbcce61564f73a2ba", SELECTED_C1),
)
PRIOR = '189b9b5959d836ef6ae96e14fb285948e4920aa9'
CONTRACT = 'config/pon/w1-qrom-implementation-current-v2.json'
AUDITOR = 'scripts/w1_qrom_current_implementation_audit.py'
TESTS = 'scripts/ci/test_w1_qrom_current_implementation_audit.py'
DOCUMENT = 'docs/security/W1_QROM_CURRENT_SOURCE_MAPPING_V2.md'
ADDED = 'trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs'
EVIDENCE = 'evidence/pon-w1-qrom-current-20261110-685a'
BASELINE_BLOBS = {
    CONTRACT: '17c1aee3547b8b21be7914b7fe2f6e1a04d9a998',
    AUDITOR: '6676a90ee5924086832f85bf967ef8713061d672',
    TESTS: 'f3297626cbf62990c2b061f12fb615467ee071ff',
    DOCUMENT: '1622af8f74183cf3a8d2ce0358dc808158ba774b',
}
ARCHIVES = {
    CONTRACT: 'historical/current-v2.json',
    AUDITOR: 'historical/current-auditor.py',
    TESTS: 'historical/current-tests.py',
    DOCUMENT: 'historical/current-mapping.md.txt',
}
NEW_PATHS = tuple(EVIDENCE + '/' + name for name in (
    'README.md', 'source-binding.json', 'current-report.json',
    'prior-v2-on-c2.command.json', 'prior-v2-on-c2.stdout.log', 'prior-v2-on-c2.stderr.log',
    *ARCHIVES.values(),
))
MAX_BYTES = 8 * 1024 * 1024
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1')


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


def regular_directory(path):
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'absolute normalized directory required')
    for item in (path, *path.parents):
        require(not item.is_symlink() and item.is_dir(), 'nonregular directory ancestry: ' + str(item))


def read_regular(path):
    require(path.is_absolute(), 'absolute path required')
    parts = path.parts[1:]
    require(parts and all(part not in ('', '.', '..') for part in parts), 'unsafe file path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES, 'nonregular or oversized file: ' + str(path))
        chunks, count = [], 0
        while count <= MAX_BYTES:
            value = os.read(descriptor, min(65536, MAX_BYTES + 1 - count))
            if not value:
                break
            chunks.append(value)
            count += len(value)
        after = os.fstat(descriptor)
        visible = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(count == before.st_size and count <= MAX_BYTES and identity(before) == identity(after) == identity(visible),
                'file changed while reading: ' + str(path))
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def write_new(path, raw, mode=0o644):
    regular_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace_expected(path, old, new):
    current, mode = read_regular(path)
    require(current == old, 'target changed before replacement: ' + str(path))
    temporary = path.parent / ('.qrom-binding-' + uuid.uuid4().hex)
    write_new(temporary, new, mode)
    try:
        require(read_regular(path)[0] == old, 'target changed while staging: ' + str(path))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def git(root, *args):
    result = subprocess.run(['git', '--no-replace-objects', *args], cwd=root, env=ENV,
                            capture_output=True, timeout=90, check=False)
    require(result.returncode == 0, 'git ' + ' '.join(args) + ': ' + result.stderr.decode(errors='replace')[-1500:])
    return result.stdout


def selected_history(root, checkpoint):
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


def entries(root, revision):
    result = {}
    for item in git(root, 'ls-tree', '-r', '-z', revision).split(b'\0'):
        if item:
            metadata, name = item.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split()
            result[name.decode()] = {'mode': mode, 'kind': kind, 'git_blob': oid}
    return result


def selected_blob(root, revision, tree, relative):
    require(type(relative) is str and str(PurePosixPath(relative)) == relative
            and not PurePosixPath(relative).is_absolute()
            and all(part not in ('', '.', '..') for part in relative.split('/')), 'unsafe selected path')
    entry = tree.get(relative)
    require(entry is not None and entry['mode'] in ('100644', '100755') and entry['kind'] == 'blob',
            'selected source is not a regular Git blob: ' + relative)
    size = int(git(root, 'cat-file', '-s', entry['git_blob']))
    require(0 < size <= MAX_BYTES, 'selected Git blob bound: ' + relative)
    raw = git(root, 'show', revision + ':' + relative)
    require(len(raw) == size and blob(raw) == entry['git_blob'], 'selected Git blob identity changed: ' + relative)
    require(read_regular(root / relative)[0] == raw, 'working source differs from selected Git commit: ' + relative)
    return raw


def methods(raw):
    return [node.name for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]


def replace_once(raw, before, after):
    before, after = before.encode(), after.encode()
    require(raw.count(before) == 1, 'nonunique reviewed source anchor: ' + before.decode()[:100])
    return raw.replace(before, after, 1)


def validate_baseline(baseline):
    require(set(baseline) == set(BASELINE_BLOBS), 'baseline path set differs')
    for path, expected in BASELINE_BLOBS.items():
        require(blob(baseline[path]) == expected, 'baseline Git pin differs: ' + path)
    contract = strict_json(baseline[CONTRACT])
    require(contract['schema'] == 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2'
            and contract['source_base_commit'] == PRIOR
            and len(contract['local_path_closure']['files']) == 137
            and len(contract['project_files']) == 16
            and len(contract['proof_obligations']) == 15, 'prior contract scope differs')
    require(len(methods(baseline[TESTS])) == 14, 'prior fourteen-test registry differs')
    return contract


def render_changes(baseline, checkpoint, tree, example):
    prior = validate_baseline(baseline)
    require(re.fullmatch('[0-9a-f]{40}', checkpoint) is not None and checkpoint != PRIOR, 'exact successor commit required')
    require(re.fullmatch('[0-9a-f]{40}', tree) is not None, 'exact successor tree required')
    current = deepcopy(prior)
    current['source_base_commit'] = checkpoint
    row = {'path': ADDED, 'bytes': len(example), 'sha256': sha(example)}
    require(row['bytes'] > 0 and ADDED not in {item['path'] for item in current['local_path_closure']['files']}, 'example already listed or empty')
    current['local_path_closure']['files'].append(row)
    current['local_path_closure']['files'].sort(key=lambda item: item['path'])
    current['reviewed_changes']['fresh_rejection_probe_20261110'] = (
        'Reviewed code checkpoint ' + checkpoint + ' adds only ' + ADDED + ' to the six-crate local closure. '
        'All previous 137 closure inputs, all 16 selected project files, existing proof materials, historical V1 reader/contract, '
        'helpers, proof parameters and 15 unresolved obligations retain their exact bytes. The old 189b9b5 descriptor, auditor, '
        'fourteen-test source and mapping document are preserved separately with their original Git blobs; the old auditor\'s '
        'actual inventory refusal on this checkpoint is retained. This is a source mapping, not a new native execution, '
        'proof verification, work-cost bound or security qualification.')
    changed = dict(baseline)
    changed[CONTRACT] = (json.dumps(current, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()
    changed[AUDITOR] = replace_once(changed[AUDITOR], "SOURCE = '" + PRIOR + "'", "SOURCE = '" + checkpoint + "'")
    changed[AUDITOR] = replace_once(changed[AUDITOR], "CONTRACT_SHA256 = '" + sha(baseline[CONTRACT]) + "'",
                                    "CONTRACT_SHA256 = '" + sha(changed[CONTRACT]) + "'")
    changed[TESTS] = replace_once(changed[TESTS], "self.assertEqual(result['source_files_checked'], 137)",
                                "self.assertEqual(result['source_files_checked'], 138)")
    changed[TESTS] = replace_once(changed[TESTS], "        self.assertIn('config/pon/work-profile-v1.json', names)",
        "        self.assertIn('config/pon/work-profile-v1.json', names)\n"
        "        self.assertIn('" + ADDED + "', names)\n"
        "        self.assertEqual(self.report['source_base_commit'], '" + checkpoint + "')")
    changed[TESTS] = replace_once(changed[TESTS],
        "        with self.assertRaisesRegex(current.AuditError, 'Rust source inventory differs'):\n            current.build_report(self.root)\n",
        "        with self.assertRaisesRegex(current.AuditError, 'Rust source inventory differs'):\n            current.build_report(self.root)\n"
        "        path.unlink()\n"
        "        # Omitting the reviewed example from a caller-supplied closure\n"
        "        # still fails the complete inventory check independently of the\n"
        "        # descriptor digest check; no examples directory is exempt.\n"
        "        omitted = json.loads(self.contract_raw)\n"
        "        omitted['local_path_closure']['files'] = [\n"
        "            row for row in omitted['local_path_closure']['files']\n"
        "            if row['path'] != '" + ADDED + "']\n"
        "        with self.assertRaisesRegex(current.AuditError, 'local Rust source inventory differs'):\n"
        "            current.local_closure(self.root, omitted)\n")
    changed[TESTS] = replace_once(changed[TESTS],
        "        path = self.root / 'trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs'\n"
        "        path.unlink()\n        with self.assertRaises(OSError):\n            current.build_report(self.root)",
        "        for relative in ('trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs',\n"
        "                         '" + ADDED + "'):\n"
        "            with self.subTest(missing_source=relative):\n"
        "                self.copy_inputs()\n                (self.root / relative).unlink()\n"
        "                with self.assertRaises(OSError):\n                    current.build_report(self.root)")
    changed[TESTS] = replace_once(changed[TESTS],
        "        value['source_base_commit'] = '0' * 40\n        path.write_text(json.dumps(value))\n"
        "        with self.assertRaisesRegex(current.AuditError, 'unreviewed current implementation contract'):\n"
        "            current.build_report(self.root)",
        "        for revision in ('0' * 40, '" + PRIOR + "'):\n"
        "            with self.subTest(stale_source=revision):\n"
        "                value['source_base_commit'] = revision\n                path.write_text(json.dumps(value))\n"
        "                with self.assertRaisesRegex(current.AuditError, 'unreviewed current implementation contract'):\n"
        "                    current.build_report(self.root)")
    archives = '\n'.join("            ('" + EVIDENCE + '/' + ARCHIVES[path] + "', '" + sha(raw) + "')," for path, raw in baseline.items())
    changed[TESTS] = replace_once(changed[TESTS],
        "        with self.assertRaisesRegex(self.audit.AuditError, 'input exceeds bound'):\n            self.audit.build_report(current.ROOT)",
        "        with self.assertRaisesRegex(self.audit.AuditError, 'input exceeds bound'):\n            self.audit.build_report(current.ROOT)\n"
        "        for relative, expected in (\n" + archives + "\n        ):\n"
        "            self.assertEqual(hashlib.sha256((current.ROOT / relative).read_bytes()).hexdigest(), expected)\n"
        "        prior = json.loads((current.ROOT / '" + EVIDENCE + "/historical/current-v2.json').read_bytes())\n"
        "        self.assertEqual(prior['source_base_commit'], '" + PRIOR + "')\n"
        "        self.assertEqual(len(prior['local_path_closure']['files']), 137)")
    require(methods(changed[TESTS]) == methods(baseline[TESTS]), 'original fourteen test identities changed')
    ast.parse(changed[AUDITOR]); ast.parse(changed[TESTS])
    addition = f'''\n\n## Reviewed follow-through source binding to `{checkpoint}`

The sections above retain their original historical source attribution. The active
V2 descriptor now describes code checkpoint `{checkpoint}`, tree `{tree}`.
The data schema and proof profile are unchanged. Its six-crate local closure
contains **138** inputs: all preceding **137** files retain their exact bytes,
and the only additional Rust input is `{ADDED}` ({len(example)} bytes,
SHA-256 `{sha(example)}`). Every `src`, `tests`, `examples` and `benches` Rust
file remains subject to the complete inventory check; no directory is exempted.

The active descriptor SHA-256 is `{sha(changed[CONTRACT])}`.
The [independent successor material](../../{EVIDENCE}/README.md) retains the
original `189b9b5` descriptor, auditor, fourteen-test source and this document,
their exact Git blob identities, and the old auditor's actual inventory refusal
on the new source. Existing evidence directories are unchanged. The new report
is a separate mapping run in the later binding child; it is not a relabeled old
receipt or a claim that the mapping tools existed at the code checkpoint.

All sixteen selected project files, saved proof materials, historical V1
reader/contract, helpers, proof parameters and fifteen unresolved obligations
remain unchanged. Every qualification stays false, every unknown lifetime
quantity stays null, and the status remains **HOLD**. This source review neither
executes a native binary nor establishes fresh proof verification, minimum work
cost, QROM soundness, open-consensus security or production admission.
'''
    changed[DOCUMENT] += addition.encode()
    expected = deepcopy(current)
    expected['source_base_commit'] = prior['source_base_commit']
    expected['local_path_closure']['files'] = [item for item in expected['local_path_closure']['files'] if item['path'] != ADDED]
    del expected['reviewed_changes']['fresh_rejection_probe_20261110']
    require(expected == prior, 'unrelated contract field changed')
    return changed, current


def run_logged(root, output, name, argv, timeout=180):
    started = time.time_ns()
    stdout, stderr = output / (name + '.stdout.log'), output / (name + '.stderr.log')
    error = None
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            result = subprocess.run(argv, cwd=root, env=ENV, stdout=out, stderr=err, timeout=timeout, check=False)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired) as failure:
            error = str(failure)
            err.write(('recorder execution failure: ' + error + '\n').encode())
            code = 124 if isinstance(failure, subprocess.TimeoutExpired) else 127
    stdout_raw, stderr_raw = read_regular(stdout)[0], read_regular(stderr)[0]
    record = {'argv': [str(item) for item in argv], 'cwd': str(root), 'exit_code': code,
              'start_unix_ns': started, 'end_unix_ns': time.time_ns(), 'launch_error': error,
              'stdout': {'file': stdout.name, 'bytes': len(stdout_raw), 'sha256': sha(stdout_raw)},
              'stderr': {'file': stderr.name, 'bytes': len(stderr_raw), 'sha256': sha(stderr_raw)}}
    write_new(output / (name + '.command.json'), encoded(record))
    return record


def logged_outputs(output, name, record):
    files = {suffix: read_regular(output / (name + '.' + suffix))[0]
             for suffix in ('command.json', 'stdout.log', 'stderr.log')}
    require(strict_json(files['command.json']) == record, 'recorded command changed: ' + name)
    for stream in ('stdout', 'stderr'):
        raw = files[stream + '.log']
        require(record[stream] == {'file': name + '.' + stream + '.log', 'bytes': len(raw), 'sha256': sha(raw)},
                'recorded command output changed: ' + name)
    return files


def verify_old_refusal(root, output):
    record = run_logged(root, output, 'prior-v2-on-c2', [sys.executable, '-B', str(root / AUDITOR), '--repo-root', str(root)])
    require(record['exit_code'] == 2 and read_regular(output / 'prior-v2-on-c2.stdout.log')[0] == b'',
            'old V2 auditor did not produce its exact expected refusal')
    report = strict_json(read_regular(output / 'prior-v2-on-c2.stderr.log')[0])
    require(report == {'schema': 'TRNM-W1-QROM-CURRENT-IMPLEMENTATION-AUDIT2', 'result': 'INPUT_REJECTED',
                       'reason': 'local Rust source inventory differs', 'production_qualified': False, 'security_bits_quantum': None},
            'old V2 refusal is unrelated to the newly inventoried example')
    return record


def historical_unchanged(root, baseline_tree):
    names = git(root, 'diff', '--name-only', '--no-renames', '-z', BASE, '--', 'evidence/', 'qualification/').split(b'\0')
    require(not {name.decode() for name in names if name} & {name for name in baseline_tree if name.startswith(('evidence/', 'qualification/'))},
            'existing historical evidence or qualification differs from baseline')


def working_rust_inventory(root, roots):
    found = set()
    def failed(error):
        raise error
    for name in roots:
        for kind in ('src', 'tests', 'examples', 'benches'):
            directory = root / name / kind
            require(not directory.is_symlink(), 'symlinked local source directory')
            if not directory.exists():
                continue
            regular_directory(directory)
            for parent, directories, files in os.walk(directory, followlinks=False, onerror=failed):
                for child in directories:
                    require(not (Path(parent) / child).is_symlink(), 'symlinked local source directory')
                for child in files:
                    if child.endswith('.rs'):
                        path = Path(parent) / child
                        require(stat.S_ISREG(path.lstat().st_mode), 'nonregular local Rust source')
                        found.add(str(path.relative_to(root)))
    return found


def verify_report(report, current, auditor_bytes):
    require(report['schema'] == 'TRNM-W1-QROM-CURRENT-IMPLEMENTATION-AUDIT2'
            and report['result'] == 'CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD'
            and report['source_base_commit'] == current['source_base_commit']
            and report['contract_sha256'] == sha((json.dumps(current, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode())
            and report['generator_sha256'] == sha(auditor_bytes), 'successor report source identity differs')
    require(report['local_path_closure']['source_files_checked'] == 138
            and report['local_path_closure']['source_before_after_equal'] is True
            and report['local_path_closure']['files'] == current['local_path_closure']['files']
            and report['local_path_closure']['literal_include_files'] == current['local_path_closure']['literal_include_files'],
            'successor report complete source inventory differs')
    require(report['qualification'] == current['qualification']
            and report['lifetime_budget'] == current['lifetime_budget']
            and report['project_files'] == current['project_files']
            and report['saved_fixture_files'] == current['saved_v2_files']
            and report['open_obligations'] == [{'id': name, 'state': 'UNRESOLVED'} for name in current['proof_obligations']],
            'successor report changes a retained mapping or security obligation')
    require(all(report[name] is False for name in ('fresh_cryptographic_verification', 'native_binary_executed',
            'whole_repository_source_verified', 'third_party_source_closure_verified', 'provider_build_identity_verified',
            'git_commit_ancestry_verified')), 'source mapping escalated execution or qualification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh external receipt directory')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    output, applied, owns_output = None, [], False
    try:
        root, output = args.root.absolute(), args.output.absolute()
        regular_directory(root); regular_directory(output.parent)
        require(str(output) == os.path.normpath(output) and not output.is_relative_to(root)
                and not output.exists() and not output.is_symlink(), 'receipt directory must be fresh and outside checkout')
        checkpoint = args.checkpoint
        require(re.fullmatch('[0-9a-f]{40}', checkpoint) is not None, 'checkpoint must be an exact commit')
        require(git(root, 'rev-parse', '--show-toplevel').decode().strip() == str(root), 'root is not a full Git worktree')
        history = selected_history(root, checkpoint)
        sparse = subprocess.run(['git', 'config', '--bool', 'core.sparseCheckout'], cwd=root, env=ENV, capture_output=True, timeout=60)
        require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b'', b'false'), 'sparse worktree refused')
        require(all(not item or item.startswith(b'H ') for item in git(root, 'ls-files', '-v', '-z').split(b'\0')),
                'nonordinary or hidden index entries refused')
        require(git(root, 'cat-file', '-t', checkpoint).strip() == b'commit', 'checkpoint is not a commit')
        git(root, 'merge-base', '--is-ancestor', BASE, checkpoint)
        git(root, 'merge-base', '--is-ancestor', checkpoint, 'HEAD')
        head = git(root, 'rev-parse', 'HEAD')
        require(head.decode().strip() == history["selected_ancestry_head"], "HEAD changed after selected-lineage check")
        tree = git(root, 'rev-parse', checkpoint + '^{tree}').decode().strip()
        before_index = git(root, 'write-tree')
        baseline_tree, source_tree = entries(root, BASE), entries(root, checkpoint)
        output.mkdir()
        owns_output = True
        preflight = run_logged(root, output, 'project-preflight', ['bash', 'scripts/project-preflight.sh'])
        require(preflight['exit_code'] == 0, 'real worktree project preflight failed')
        baseline = {path: selected_blob(root, BASE, baseline_tree, path) for path in BASELINE_BLOBS}
        prior = validate_baseline(baseline)
        for path in BASELINE_BLOBS:
            require(source_tree.get(path) == baseline_tree[path]
                    and git(root, 'show', checkpoint + ':' + path) == baseline[path],
                    'checkpoint binding input differs from reviewed baseline: ' + path)
        require(not (root / EVIDENCE).exists() and not (root / EVIDENCE).is_symlink(), 'successor evidence already exists')
        historical_unchanged(root, baseline_tree)
        selected = {}
        rows = prior['local_path_closure']['files'] + prior['project_files'] + prior['saved_v2_files'] + prior['audit_helpers']
        rows += [prior['upstream_snapshot'], prior['historical_contract'], prior['historical_reader']]
        for row in rows:
            relative = row['path']
            if relative not in selected:
                selected[relative] = selected_blob(root, checkpoint, source_tree, relative)
            require(len(selected[relative]) == row['bytes'] and sha(selected[relative]) == row['sha256'],
                    'an existing selected source pin changed: ' + relative)
        require(ADDED not in baseline_tree, 'added example already existed in baseline Git')
        example = selected_blob(root, checkpoint, source_tree, ADDED)
        selected[ADDED] = example
        roots = prior['local_path_closure']['crate_roots']
        def covered(relative):
            return relative.endswith('.rs') and any(relative.startswith(name + '/' + kind + '/')
                for name in roots for kind in ('src', 'tests', 'examples', 'benches'))
        expected_rust = {row['path'] for row in prior['local_path_closure']['files'] if row['path'].endswith('.rs')} | {ADDED}
        require({name for name in source_tree if covered(name)} == expected_rust, 'checkpoint adds or removes another selected Rust file')
        require(working_rust_inventory(root, roots) == expected_rust, 'working checkout contains another selected Rust source change')
        for name in prior['local_path_closure']['absent_build_inputs']:
            require(name not in source_tree and not (root / name).exists() and not (root / name).is_symlink(), 'unreviewed build input: ' + name)
        old_refusal = verify_old_refusal(root, output)
        updated, current = render_changes(baseline, checkpoint, tree, example)
        patch = ''.join('diff --git a/' + path + ' b/' + path + '\n' + ''.join(difflib.unified_diff(
            baseline[path].decode().splitlines(keepends=True), updated[path].decode().splitlines(keepends=True),
            fromfile='a/' + path, tofile='b/' + path)) for path in BASELINE_BLOBS)
        write_new(output / 'review.patch', patch.encode())
        records = [{'path': path, 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': source_tree[path]['git_blob']}
                   for path, raw in sorted(selected.items())]
        review = {'schema': 'trnm-qrom-v2-successor-binding-review-v2', 'baseline': BASE, 'prior_source': PRIOR, **history,
                  'code_checkpoint': checkpoint, 'code_checkpoint_tree': tree, 'head_before': head.decode().strip(),
                  'existing_closure_count': 137, 'successor_closure_count': 138, 'only_added_closure_path': ADDED,
                  'selected_git_blobs': records, 'mutable_paths': list(BASELINE_BLOBS), 'new_paths': list(NEW_PATHS),
                  'native_binary_executed': False, 'production_qualified': False, 'security_bits_quantum': None}
        write_new(output / 'review.json', encoded(review))

        def unchanged(targets):
            require(git(root, 'rev-parse', 'HEAD') == head and git(root, 'write-tree') == before_index, 'HEAD or index changed')
            for path, raw in selected.items():
                require(read_regular(root / path)[0] == raw, 'selected source changed during binding: ' + path)
                require(git(root, 'show', checkpoint + ':' + path) == raw, 'selected commit source changed: ' + path)
            for path, raw in targets.items():
                require(read_regular(root / path)[0] == raw, 'binding target changed: ' + path)
            require(working_rust_inventory(root, roots) == expected_rust, 'working Rust inventory changed during binding')
            for name in prior['local_path_closure']['absent_build_inputs']:
                require(not (root / name).exists() and not (root / name).is_symlink(), 'build input appeared during binding: ' + name)
            historical_unchanged(root, baseline_tree)

        unchanged(baseline)
        if not args.apply:
            write_new(output / 'result.json', encoded({'status': 'PREPARED_NO_WRITES', 'review': 'review.json', 'applied': []}))
            print(json.dumps({'status': 'PREPARED_NO_WRITES', 'output': str(output)}, sort_keys=True))
            return 0
        destination = root / EVIDENCE
        regular_directory(destination.parent)
        destination.mkdir()
        (destination / 'historical').mkdir()
        new_files = {}
        def emit(name, raw):
            relative = EVIDENCE + '/' + name
            require(relative in NEW_PATHS and relative not in new_files, 'unreviewed or duplicate new artifact')
            write_new(destination / name, raw)
            applied.append(relative)
            new_files[relative] = raw
        for path, raw in baseline.items():
            emit(ARCHIVES[path], raw)
        for suffix, raw in logged_outputs(output, 'prior-v2-on-c2', old_refusal).items():
            emit('prior-v2-on-c2.' + suffix, raw)
        for path, raw in updated.items():
            replace_expected(root / path, baseline[path], raw); applied.append(path)
        unchanged(updated)
        map_command = run_logged(root, output, 'successor-mapping', [sys.executable, '-B', str(root / AUDITOR),
            '--repo-root', str(root), '--output', str(output / 'current-report.json')])
        require(map_command['exit_code'] == 0, 'successor mapping failed; original outputs retained')
        report_raw = read_regular(output / 'current-report.json')[0]
        report = strict_json(report_raw)
        verify_report(report, current, updated[AUDITOR])
        controls = run_logged(root, output, 'successor-fourteen-controls', [sys.executable, '-B', str(root / TESTS), '-v'])
        control_log = logged_outputs(output, 'successor-fourteen-controls', controls)['stderr.log']
        logged_outputs(output, 'successor-mapping', map_command)
        require(controls['exit_code'] == 0 and re.search(rb'\nRan 14 tests in [^\n]+\n\nOK\n', control_log) is not None,
                'successor fourteen controls failed or were not completely observed')
        require(not re.search(rb'\bskipped\b|\bexpected failure\b|\bunexpected success\b', control_log), 'successor controls include non-success outcomes')
        unchanged(updated)
        for path, raw in baseline.items():
            require(read_regular(destination / ARCHIVES[path])[0] == raw, 'preserved prior V2 bytes changed')
        emit('current-report.json', report_raw)
        receipt = dict(review, status='SUCCESSOR_MAPPING_REPRODUCED_SECURITY_HOLD',
            prior_binding_inputs=[{'path': path, 'archive': ARCHIVES[path], 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw)}
                                  for path, raw in baseline.items()],
            active_binding_outputs=[{'path': path, 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw)} for path, raw in updated.items()],
            prior_refusal=old_refusal, current_mapping_command=map_command, fourteen_controls_command=controls,
            current_report={'path': 'current-report.json', 'bytes': len(report_raw), 'sha256': sha(report_raw)},
            original_test_method_names=methods(baseline[TESTS]), current_test_method_names=methods(updated[TESTS]),
            current_descriptor_sha256=sha(updated[CONTRACT]), qualification=prior['qualification'],
            lifetime_budget=prior['lifetime_budget'], proof_obligations=prior['proof_obligations'],
            mapping_tool_location='later-uncommitted-binding-child-of-code-checkpoint',
            hosted_ci_observed=False, native_execution_inferred=False)
        emit('source-binding.json', encoded(receipt))
        readme = f'''# W1 QROM V2 successor source mapping, 2026-11-10

Status: **source mapping reproduced; cryptographic and production qualification HOLD**.

The selected code checkpoint is `{checkpoint}`, tree `{tree}`. The current mapping
and its bindings are created in a later child; they are not claimed to have existed
at that checkpoint. All previous 137 local inputs were read from that real commit
and compared byte-for-byte with the working checkout and original pins. The only
new selected Rust input is `{ADDED}` ({len(example)} bytes, SHA-256 `{sha(example)}`).
All 138 inputs and the complete six-crate Rust inventory are checked before and
after the new mapping. This source recorder does not execute a native binary.

## Preserved prior binding and actual refusal

The [old descriptor](historical/current-v2.json), [old auditor](historical/current-auditor.py),
[old fourteen-test source](historical/current-tests.py) and [old mapping document](historical/current-mapping.md.txt)
are exact copies of the `da1374a` Git blobs for the source map attributed to
`{PRIOR}`. Their SHA-256 and Git blob identities are in [source-binding.json](source-binding.json).
The copied document retains its original relative links and is a byte archive,
not a relocated operational entry point. All existing historical evidence stays
unchanged. Before rebinding, that old active auditor was actually executed on the
new code and returned exit 2 with `local Rust source inventory differs`.
Its [command](prior-v2-on-c2.command.json), [stdout](prior-v2-on-c2.stdout.log) and
[stderr](prior-v2-on-c2.stderr.log) are retained verbatim. That failure remains a failure.

## Independent successor observation

[current-report.json](current-report.json) is newly generated by the successor
auditor, with descriptor SHA-256 `{sha(updated[CONTRACT])}` and report SHA-256
`{sha(report_raw)}`. Fourteen original method identities are retained; their real
Python control run adds subcases for the stale prior source, missing new example,
and omitted inventory entry. The controller keeps complete command streams in
its external receipt directory. Subsequent candidate/workflow checks have their
own source brackets; this report does not claim hosted CI completion.

The existing schema, proof profile, sixteen project pins, saved proof materials,
V1 reader/contract, three pure mapping helpers, proof parameters and all fifteen
unresolved obligations remain unchanged. Qualification flags remain false and
unknown lifetime quantities remain null. This observation establishes no new
proof verification, QROM reduction, cheapest work cost, consensus failure bound,
provider/build identity or production admission.
'''
        emit('README.md', readme.encode())
        require(set(applied) == set(BASELINE_BLOBS) | set(NEW_PATHS), 'applied path set differs from reviewed scope')
        unchanged(updated)
        for path, raw in new_files.items():
            require(read_regular(root / path)[0] == raw, 'new evidence changed during binding: ' + path)
        write_new(output / 'result.json', encoded({'status': 'APPLIED_MAPPING_AND_FOURTEEN_CONTROLS_SECURITY_HOLD',
            'schema': 'trnm-qrom-v2-successor-binding-result-v2', **history,
            'applied': applied, 'code_checkpoint': checkpoint, 'code_checkpoint_tree': tree,
            'native_binary_executed': False, 'hosted_ci_observed': False, 'production_qualified': False}))
        print(json.dumps({'status': 'APPLIED_MAPPING_AND_FOURTEEN_CONTROLS_SECURITY_HOLD', 'output': str(output),
                          'changed_files': len(applied), 'source': checkpoint}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = {'status': 'REFUSE', 'reason': str(error), 'applied': applied,
                   'automatic_rollback_performed': False, 'native_binary_executed': False, 'production_qualified': False}
        if owns_output and output is not None and output.is_dir() and not (output / 'failure.json').exists():
            write_new(output / 'failure.json', encoded(failure))
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
