#!/usr/bin/env python3
"""Materialize one authenticated historical Git blob without changing source or refs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/qian-qi/chain-pon-followthrough-20261110-685a')
INPUTS = Path(str(ROOT) + '-inputs')
OUT = INPUTS / 'historical-lock-materialization-01'
INPUT = INPUTS / 'historical-Cargo-lock-7dd.bytes'
HEAD = 'a715b2c8e89732ce356ebae67f978ef232156c04'
HISTORICAL = '7ddfe2bfa480d1ebd91c07d03d56a963fff038c5'
SELECTOR = HISTORICAL + ':trillionnium/Cargo.lock'
BLOB = '2ff1e1c42dfa7061f4a77620c0bb65b656d158a5'
SHA256 = 'f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd'
ENV = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
ROWS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def emit(name, value):
    path = OUT / name
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    tmp.replace(path)


def run(label, argv, *, data=None, timeout=30):
    emit('status.json', {'stage': label, 'phase': 'running', 'security_status': 'HOLD'})
    start = time.time_ns()
    error = None
    try:
        result = subprocess.run(argv, cwd=ROOT, env=ENV, input=data, capture_output=True,
                                timeout=timeout, check=False)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as failure:
        code, stdout = 124, failure.stdout or b''
        stderr = (failure.stderr or b'') + b'\nhistorical object preparation timeout\n'
        error = repr(failure)
    row = {'label': label, 'argv': argv, 'cwd': str(ROOT), 'exit_code': code,
           'launch_error': error,
           'start_unix_ns': start, 'end_unix_ns': time.time_ns()}
    for stream_name, raw in [('stdout', stdout), ('stderr', stderr)]:
        path = OUT / (label + '.' + stream_name + '.log')
        with path.open('xb') as stream:
            stream.write(raw)
        row[stream_name] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
    if data is not None:
        row['stdin'] = {'bytes': len(data), 'sha256': sha(data)}
    ROWS.append(row)
    emit('commands.json', ROWS)
    if code:
        raise RuntimeError(label + ' actual exit ' + str(code))
    return stdout


def snapshot(prefix):
    values = {}
    for name, argv in [
        ('head', ['git', 'rev-parse', 'HEAD']),
        ('tree', ['git', 'write-tree']),
        ('status', ['git', 'status', '--porcelain']),
        ('index-flags', ['git', 'ls-files', '-v', '-z']),
        ('shallow', ['git', 'rev-parse', '--is-shallow-repository']),
    ]:
        values[name] = run(prefix + '-' + name, argv)
    assert values['head'].decode().strip() == HEAD
    assert values['status'] == b''
    assert all(not row or row.startswith(b'H ') for row in values['index-flags'].split(b'\0'))
    return values


assert not OUT.exists()
OUT.mkdir()
try:
    raw = INPUT.read_bytes()
    assert len(raw) == 40365 and sha(raw) == SHA256
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == BLOB
    run('project-preflight', ['bash', 'scripts/project-preflight.sh'])
    before = snapshot('before')
    commit = run('historical-commit', ['git', '--no-replace-objects', 'cat-file', 'commit', HISTORICAL])
    assert hashlib.sha1(b'commit ' + str(len(commit)).encode() + b'\0' + commit).hexdigest() == HISTORICAL
    assert commit.startswith(b'tree d0fd1180a193e2caafd9ef6818f28bf571a9240b\n')
    assert run('historical-path-identity', ['git', '--no-replace-objects', 'rev-parse', SELECTOR]).decode().strip() == BLOB
    observed = run('materialize-exact-blob', ['git', 'hash-object', '-w', '--stdin'], data=raw)
    assert observed.decode().strip() == BLOB
    recovered = run('original-historical-read', ['git', '--no-replace-objects', 'show', SELECTOR], timeout=15)
    assert recovered == raw
    after = snapshot('after')
    assert before == after
    summary = {'schema': 'pon-historical-lock-materialization-v1', 'complete': True,
               'source_commit': HEAD, 'historical_commit': HISTORICAL, 'historical_path': SELECTOR,
               'historical_blob': BLOB, 'bytes': len(raw), 'sha256': SHA256,
               'current_head_tree_index_status_and_shallow_state_identical': True,
               'git_ref_mutation_commands_executed': [], 'project_source_changed': False,
               'object_store_write_performed': True, 'native_tests_executed': False,
               'historical_15_second_read_passed': True, 'original_failed_read_retained': True,
               'open_consensus_qualified': False, 'production_activation': False,
               'security_status': 'HOLD', 'recorder_sha256': sha(Path(__file__).read_bytes())}
    emit('summary.json', summary)
    emit('status.json', {'stage': 'complete', 'phase': 'finished', 'exit_code': 0, 'security_status': 'HOLD'})
    print(json.dumps(summary), flush=True)
except BaseException as error:
    emit('failure.json', {'complete': False, 'reason': repr(error), 'security_status': 'HOLD',
                          'no_automatic_rollback': True})
    emit('status.json', {'stage': 'failure', 'phase': 'failed', 'exit_code': 1, 'security_status': 'HOLD'})
    raise
