#!/usr/bin/env python3
"""Map the original W1 contract from its exact historical Git blobs.

This separate entry never changes the historical reader or its pins. Project
files come only from the contract's existing commit; pinned helpers and saved
artifacts come from the current checkout. Missing objects fail without a fetch
or a working-tree fallback. A separate observation retains the original
reader's refusal of the actual current tree. Neither result qualifies it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import w1_qrom_implementation_audit as audit

sys.path.insert(0, str(Path(__file__).resolve().parent / 'ci'))
from pq_source_reader import read_regular

READER = 'scripts/w1_qrom_implementation_audit.py'
READER_SHA256 = 'c6fc6c36e4c2ce198c1dad465a7d36495253f844438f46df652715ea6dc8b354'
CURRENT_REFUSAL = 'input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs'
MATERIALIZATION_SCHEMA = 'TRNM-W1-QROM-HISTORICAL-MATERIALIZATION1'
REFUSAL_SCHEMA = 'TRNM-W1-QROM-HISTORICAL-CURRENT-REFUSAL1'
OUTPUT_NAMES = ('implementation.json', 'historical-source.json', 'current-v1-refusal.json')


def git(repo_root, *args):
    """Read existing objects; disable replacements and implicit remote fetches."""
    environment = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0')
    for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
                 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
        environment.pop(name, None)
    return subprocess.check_output(['git', '--no-replace-objects', *args],
                                   cwd=repo_root, env=environment,
                                   stderr=subprocess.PIPE, timeout=15)


def read_project_blob(repo_root, commit, row):
    """Bind a regular Git entry, exact object size, and the original SHA-256."""
    audit.require(type(commit) is str and re.fullmatch(r'[0-9a-f]{40}', commit),
                  'historical source commit identity')
    audit.require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'},
                  'historical source record fields')
    path, size, digest = row['path'], row['bytes'], row['sha256']
    audit.require(type(path) is str and path and '\\' not in path and '\0' not in path
                  and ':' not in path
                  and all(part not in ('', '.', '..') for part in path.split('/')),
                  'historical source path')
    audit.require(type(size) is int and 0 < size <= 2 * 1024 * 1024,
                  'historical source byte bound: ' + path)
    audit.require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
                  'historical source digest: ' + path)
    audit.require(git(repo_root, 'cat-file', '-t', commit) == b'commit\n',
                  'historical source object is not a commit')
    entry = git(repo_root, 'ls-tree', '-z', '--full-tree', commit, '--', path)
    audit.require(entry.endswith(b'\0') and entry.count(b'\0') == 1,
                  'one historical source entry required: ' + path)
    header, separator, name = entry[:-1].partition(b'\t')
    fields = header.split()
    audit.require(separator and name == path.encode() and len(fields) == 3
                  and fields[0] in (b'100644', b'100755') and fields[1] == b'blob'
                  and re.fullmatch(rb'[0-9a-f]{40}', fields[2]),
                  'historical source is not a regular Git blob: ' + path)
    object_id = fields[2].decode()
    audit.require(git(repo_root, 'cat-file', '-t', object_id) == b'blob\n',
                  'historical source object type: ' + path)
    audit.require(git(repo_root, 'cat-file', '-s', object_id) == str(size).encode() + b'\n',
                  'historical source exact size: ' + path)
    raw = git(repo_root, 'cat-file', 'blob', object_id)
    audit.require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
                  'historical source exact digest: ' + path)
    return raw, {**row, 'git_mode': fields[0].decode(), 'git_blob_oid': object_id}


def historical_project_file(repo_root, commit, row):
    return read_project_blob(repo_root, commit, row)[0]


def fixture_inputs(repo_root):
    """Return immutable bytes; only the caller's private fixture will be written."""
    root = Path(repo_root).absolute()
    audit.require(root == root.resolve(strict=True), 'historical fixture root/ancestor is an alias')
    reader = read_regular(root, READER, 2 * 1024 * 1024)
    audit.require(audit.sha(reader) == READER_SHA256, 'historical reader differs')
    contract_raw = read_regular(root, audit.CONTRACT, 65536)
    contract, checked_raw = audit.load_contract(root)
    audit.require(contract_raw == checked_raw, 'historical contract changed during read')
    files = {audit.CONTRACT: contract_raw}
    records = []
    for row in contract['project_files']:
        raw, record = read_project_blob(root, contract['source_base_commit'], row)
        audit.require(row['path'] not in files, 'duplicate historical fixture path')
        files[row['path']] = raw
        records.append(record)
    pinned = (contract['audit_helpers'] + contract['saved_v2_files']
              + [contract['upstream_snapshot']])
    for row in pinned:
        raw = read_regular(root, row['path'], row['bytes'])
        audit.require(len(raw) == row['bytes'] and audit.sha(raw) == row['sha256'],
                      'historical pinned fixture differs: ' + row['path'])
        audit.require(row['path'] not in files, 'duplicate historical fixture path')
        files[row['path']] = raw
    receipt = {
        'schema': MATERIALIZATION_SCHEMA,
        'historical_source_commit': contract['source_base_commit'],
        'historical_contract_sha256': audit.sha(contract_raw),
        'historical_reader_sha256': READER_SHA256,
        'project_files': records,
        'pinned_checkout_inputs': pinned,
        'scope': 'historical-declared-project-blobs-and-pinned-fixtures-only',
        'historical_full_repository_checked': False,
        'current_project_mapping': False,
        'fresh_cryptographic_verification': False,
        'qualification': dict(audit.QUALIFICATION),
    }
    return contract, files, receipt


def historical_mapping(repo_root):
    contract, files, receipt = fixture_inputs(repo_root)
    with tempfile.TemporaryDirectory(prefix='w1-historical-inputs-') as directory:
        fixture = Path(directory)
        for relative, raw in files.items():
            destination = fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as stream:
                stream.write(raw)
        report = audit.build_report(fixture)
    audit.require(report['source_base_commit'] == contract['source_base_commit']
                  and report['qualification'] == audit.QUALIFICATION,
                  'historical report identity or qualification differs')
    return report, receipt


def current_v1_refusal(repo_root):
    """Record the actual old reader's rejection, without treating it as v2."""
    root = Path(repo_root).absolute()
    audit.require(audit.sha(read_regular(root, READER, 2 * 1024 * 1024)) == READER_SHA256,
                  'historical reader differs')
    contract, raw = audit.load_contract(root)
    try:
        audit.build_report(root)
    except audit.AuditError as error:
        reason = str(error)
        audit.require(reason == CURRENT_REFUSAL, 'unexpected current-tree historical refusal: ' + reason)
    else:
        raise audit.AuditError('historical reader unexpectedly accepted the current tree')
    return {
        'schema': REFUSAL_SCHEMA, 'result': 'INPUT_REJECTED', 'reason': reason,
        'historical_source_commit': contract['source_base_commit'],
        'historical_contract_sha256': audit.sha(raw),
        'historical_reader_sha256': READER_SHA256,
        'target': 'actual-current-worktree',
        'current_source_mapping_performed': False,
        'qualification': dict(audit.QUALIFICATION),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=audit.ROOT)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        audit.require(args.output_dir.is_dir() and not args.output_dir.is_symlink(),
                      'existing regular output directory required')
        audit.require(not any((args.output_dir / name).exists()
                              or (args.output_dir / name).is_symlink() for name in OUTPUT_NAMES),
                      'existing historical observation will not be replaced')
        report, receipt = historical_mapping(args.repo_root)
        refusal = current_v1_refusal(args.repo_root)
        for name, data in zip(OUTPUT_NAMES, (report, receipt, refusal)):
            with (args.output_dir / name).open('x') as stream:
                json.dump(data, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write('\n')
        print(json.dumps({'result': 'HISTORICAL_MAPPING_AND_CURRENT_REFUSAL_RECORDED',
                          'historical_source_commit': receipt['historical_source_commit'],
                          'qualification': audit.QUALIFICATION}, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'result': 'INPUT_REJECTED', 'reason': str(error),
                          'qualification': audit.QUALIFICATION}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
