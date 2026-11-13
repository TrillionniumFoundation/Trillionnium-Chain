#!/usr/bin/env python3
"""Observe the exact integrated child with the unchanged native lint gate.

Does not mutate source, publish, or credit C2's executions to its child.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
VERIFY = 'scripts/ci/verify_ci_source.py'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, obj):
    raw = (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode()
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--integration-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    root, previous, out = args.root, args.integration_output, args.output
    for path in (root, previous, out, args.target):
        assert path.is_absolute() and path == path.resolve(), 'absolute normalized non-symlink paths required'
    assert not out.is_relative_to(root) and not out.exists()
    assert not args.target.is_relative_to(root)
    for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
                 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT'):
        assert not os.environ.get(name), 'external Git override refused: ' + name
    env = dict(os.environ, CARGO_TERM_COLOR='never', CARGO_BUILD_JOBS='2',
               CARGO_TARGET_DIR=str(args.target), CARGO_NET_OFFLINE='true',
               PYTHONDONTWRITEBYTECODE='1', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
    def git(*argv):
        return subprocess.check_output(['git', '--no-replace-objects', *argv], cwd=root, env=env)
    def gtext(*argv):
        return git(*argv).decode().strip()
    integrated = json.loads((previous / 'summary.json').read_bytes())
    assert integrated['integration_complete'] is True and integrated['state'] == 'validated'
    assert integrated['code_checkpoint_c2'] == C2
    assert integrated['open_consensus_qualified'] is False and integrated['production_activation'] is False
    head, tree = gtext('rev-parse', 'HEAD'), gtext('rev-parse', 'HEAD^{tree}')
    assert head == integrated['binding_child_c3'] and tree == integrated['binding_child_tree']
    assert not git('status', '--porcelain')
    assert all(not row or row.startswith(b'H ') for row in git('ls-files', '-v', '-z').split(b'\0'))
    assert git('show', BASE + ':' + VERIFY) == git('show', head + ':' + VERIFY)
    changed = gtext('diff', '--name-only', C2, head).splitlines()
    native_changed = [p for p in changed if p.endswith('.rs') or Path(p).name in ('Cargo.toml', 'Cargo.lock')]
    assert native_changed == [INVENTORY], native_changed
    out.mkdir()
    records = []
    source = {'recorder_sha256': digest(Path(__file__).read_bytes()),
              'code_checkpoint_c2': C2, 'binding_child_c3': head, 'binding_child_tree': tree,
              'native_changed_from_c2': native_changed, 'cargo_graph_inputs_unchanged': True,
              'full_native_suites_execution_source': C2, 'child_full_suites_repeated': False,
              'explicit_environment': {key: env[key] for key in ('CARGO_TERM_COLOR', 'CARGO_BUILD_JOBS',
                  'CARGO_TARGET_DIR', 'CARGO_NET_OFFLINE', 'PYTHONDONTWRITEBYTECODE')},
              'open_consensus_qualified': False, 'production_activation': False}
    write_json(out / 'source.json', source)
    def status(label, phase, code=None):
        write_json(out / 'status.json', {'stage': label, 'phase': phase, 'last_exit': code,
            'binding_child_c3': head, 'recorded_unix_ns': time.time_ns(), 'security_status': 'HOLD'})
    def run(label, argv, required=True, timeout=1800):
        start = time.time_ns()
        status(label, 'running')
        print('START', label, flush=True)
        stdout, stderr = out / (label + '.stdout.log'), out / (label + '.stderr.log')
        with stdout.open('xb') as output, stderr.open('xb') as error:
            try:
                result = subprocess.run(argv, cwd=root, env=env, stdout=output, stderr=error, timeout=timeout)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
                error.write(b'\nRecorder: explicit 1800-second command budget expired.\n')
        row = {'label': label, 'argv': argv, 'cwd': str(root), 'exit_code': code,
               'start_unix_ns': start, 'end_unix_ns': time.time_ns()}
        for key, path in (('stdout', stdout), ('stderr', stderr)):
            raw = path.read_bytes()
            row[key] = {'file': path.name, 'bytes': len(raw), 'sha256': digest(raw)}
        records.append(row)
        write_json(out / 'commands.json', records)
        status(label, 'finished' if code == 0 else 'failed', code)
        print('END', label, code, flush=True)
        if required and code:
            raise RuntimeError('actual command failed: ' + label)
        return code
    try:
        run('preflight', ['bash', 'scripts/project-preflight.sh'])
        source_cmd = ['python3', '-B', VERIFY, '--kind', 'head', '--expected-head', head, '--output']
        run('source-before', source_cmd + [str(out / 'source-before.json')])
        run('locked-graph', ['cargo', 'metadata', '--manifest-path', 'trillionnium/Cargo.toml',
                            '--locked', '--offline', '--format-version', '1'])
        run('changed-owner-clippy', ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml',
            '--locked', '--offline', '-p', 'trnm-pon-node', '-p', 'trnm-service-settlement',
            '-p', 'trnm-crypto-primitives', '--all-targets', '--', '-D', 'warnings'])
        run('source-after', source_cmd + [str(out / 'source-after.json')])
        run('source-identical', ['cmp', str(out / 'source-before.json'), str(out / 'source-after.json')])
        assert gtext('rev-parse', 'HEAD') == head and not git('status', '--porcelain')
        before = json.loads((out / 'source-before.json').read_bytes())
        assert before['tested_commit'] == head and before['tested_tree'] == tree
        assert before['tracked_worktree_verified'] is True
        summary = dict(source, schema='pon-followthrough-binding-child-native-checks-v1', complete=True,
                       commands=len(records), strict_clippy_passed=True, security_status='HOLD')
        write_json(out / 'summary.json', summary)
        status('complete', 'finished', 0)
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 0
    except (AssertionError, RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        write_json(out / 'failure.json', {'complete': False, 'reason': str(error), 'source': source,
                                         'recorded_unix_ns': time.time_ns(), 'security_status': 'HOLD'})
        status('validation', 'failed', 2)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
