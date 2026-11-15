#!/usr/bin/env python3
"""Verify retained bytes only; never promote execution or PQ qualification."""
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
ROOT = Path(__file__).resolve().parent
LIMIT = 4 * 1024 * 1024
GROUPS = (('preliminary', 'index.json'), ('attempt-1f7ff410', 'archive-index.json'), ('attempt-a44344b2', 'archive-index.json'), ('hosted-a44344b2', 'archive-index.json'))

def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    require(path.is_file() and (not path.is_symlink()), str(path))
    require(path.stat().st_size <= LIMIT, str(path))
    with path.open('rb') as stream:
        data = stream.read(LIMIT + 1)
    require(len(data) <= LIMIT, str(path))
    return data

def relative_path(value):
    require(type(value) is str and value, 'archive mismatch')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts, 'archive mismatch')
    require(path.as_posix() == value, 'archive mismatch')
    return path

def main():
    checked = []
    for name, index in GROUPS:
        folder = ROOT / name
        manifest = json.loads(read(folder / index))
        rows = manifest['files']
        require(type(rows) is list and 0 < len(rows) <= 256, 'archive mismatch')
        seen = set()
        raw_files = {}
        for row in rows:
            stored = relative_path(row['stored_path'])
            original = relative_path(row['original_name'])
            require(str(stored) not in seen, 'archive mismatch')
            seen.add(str(stored))
            data = read(folder / stored)
            require(len(data) == row['stored_bytes'], 'archive mismatch')
            require(hashlib.sha256(data).hexdigest() == row['stored_sha256'], 'archive mismatch')
            require(type(row['compressed']) is bool, 'archive mismatch')
            if row['compressed']:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    data = stream.read(LIMIT + 1)
            require(len(data) <= LIMIT and len(data) == row['raw_bytes'], 'archive mismatch')
            require(hashlib.sha256(data).hexdigest() == row['raw_sha256'], 'archive mismatch')
            require(str(original) not in raw_files, 'archive mismatch')
            raw_files[str(original)] = data
        result = {'group': name, 'verified_files': len(rows)}
        if name.startswith('attempt-'):
            before = json.loads(raw_files['source-before.json'])
            after = json.loads(raw_files['source-after.json'])
            require(before == after and before['tracked_worktree_verified'] is True, 'archive mismatch')
            commands = json.loads(raw_files['commands.json'])
            require(len(commands) == 35, 'archive mismatch')
            for row in commands:
                data = raw_files[row['log']]
                require(row['source'] == before['tested_commit'], 'archive mismatch')
                require(len(data) == row['bytes'], 'archive mismatch')
                require(hashlib.sha256(data).hexdigest() == row['sha256'], 'archive mismatch')
            summary = json.loads(raw_files['summary.json'])
            require(summary['source'] == before['tested_commit'], 'archive mismatch')
            require(summary['source_unchanged'] is True, 'archive mismatch')
            require(summary['commands_total'] == len(commands), 'archive mismatch')
            require(summary['commands_passed'] == sum((x['exit_code'] == 0 for x in commands)), 'archive mismatch')
            require(summary['status'] == 'HOLD', 'archive mismatch')
            require(summary['actual_lifetime_failure_bound'] is None, 'archive mismatch')
            for flag in ('whole_chain_pq_qualified', 'composition_coverage_proved', 'production_activation', 'full_protocol_lane_executed', 'full_workspace_tests_executed'):
                require(summary[flag] is False, 'archive mismatch')
            result.update(source=before['tested_commit'], commands_passed=summary['commands_passed'], commands_total=len(commands))
        checked.append(result)
    print(json.dumps({'archive_bytes_verified': True, 'groups': checked, 'independent_provenance_authenticated': False, 'status': 'HOLD', 'whole_chain_pq_qualified': False}, indent=2))
if __name__ == '__main__':
    main()
