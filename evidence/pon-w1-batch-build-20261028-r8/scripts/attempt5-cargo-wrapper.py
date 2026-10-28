#!/usr/bin/python3
"""Attempt5: restore exactly four intended Cargo build constraints.

The upstream SDK deliberately sanitizes CARGO variables for guest compilation.
This wrapper preserves its argv, RUSTC, encoded flags, HOME and every other env
variable. It neither downloads dependencies nor changes SDK/version checks.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

CARGO = '/tmp/pure-pon-toolchain-20261027/bin/cargo'
CARGO_SHA256 = '841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'
LOG = '/tmp/w1-batch-phase0-attempt5-20261028-r8/cargo-wrapper.jsonl'
RESTORE = {
    'CARGO_HOME': '/tmp/pure-pon-cargo-20261027',
    'CARGO_NET_OFFLINE': 'true',
    'CARGO_BUILD_JOBS': '1',
    'CARGO_INCREMENTAL': '0',
}


def sha256(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    source_hash = sha256(__file__)
    if os.environ.get('TRNM_W1_CARGO_WRAPPER_SHA256') != source_hash:
        raise RuntimeError('wrapper source hash was not bound by the pipeline')
    if os.environ.get('TRNM_W1_CARGO_WRAPPER_LOG') != LOG:
        raise RuntimeError('unexpected wrapper audit destination')
    if sha256(CARGO) != CARGO_SHA256:
        raise RuntimeError('fixed native cargo binary changed')
    before = dict(os.environ)
    after = dict(before)
    after.update(RESTORE)
    changed = {key for key in before.keys() | after.keys()
               if before.get(key) != after.get(key)}
    if not changed <= RESTORE.keys():
        raise RuntimeError('unexpected environment mutation')
    argv = [CARGO, *sys.argv[1:]]
    row = {
        'schema': 'TRNM-W1-BATCH-CARGO-WRAPPER1',
        'unix_ns': time.time_ns(), 'source_sha256': source_hash,
        'exec_path': CARGO, 'exec_sha256': CARGO_SHA256, 'argv': argv,
        'restored_environment': RESTORE, 'changed_environment_keys': sorted(changed),
        'sdk_rustc_preserved': after.get('RUSTC') == before.get('RUSTC'),
        'sdk_rustc_path': after.get('RUSTC'),
        'sdk_encoded_flags_preserved': after.get('CARGO_ENCODED_RUSTFLAGS')
            == before.get('CARGO_ENCODED_RUSTFLAGS'),
        'home_preserved': after.get('HOME') == before.get('HOME'),
        'argv_tail_unchanged': argv[1:] == sys.argv[1:],
    }
    path = Path(LOG)
    if path.exists() and path.stat().st_size > 256 * 1024:
        raise RuntimeError('wrapper audit log unexpectedly large')
    with path.open('a') as handle:
        handle.write(json.dumps(row, sort_keys=True) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.execve(CARGO, argv, after)


if __name__ == '__main__':
    main()
