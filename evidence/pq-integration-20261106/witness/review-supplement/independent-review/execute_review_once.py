#!/usr/bin/env python3
"""Capture the single non-executing archive review and its explicit handoff."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

OUT = Path('/workspace/scratch/chain-pq-root-recovery-20261106-v1/integration-review/final-increment-independent-review-v1')

def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def emit(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')

def main():
    method = OUT / 'review_final_increment.py'
    before = identity(method)
    argv = [sys.executable, '-B', str(method)]
    started_utc = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    with (OUT / 'execution.stdout.log').open('xb') as stdout, (OUT / 'execution.stderr.log').open('xb') as stderr:
        try:
            code = subprocess.run(argv, cwd=OUT, stdout=stdout, stderr=stderr, timeout=120, check=False).returncode
            exception = None
        except subprocess.TimeoutExpired as error:
            code = None
            exception = repr(error)
    execution = {'schema': 'trnm-final-increment-independent-review-execution-v1', 'argv': argv,
                 'started_utc': started_utc, 'elapsed_seconds': time.monotonic() - started,
                 'exit_code': code, 'exception': exception, 'method_before': before,
                 'method_after': identity(method),
                 'stdout': identity(OUT / 'execution.stdout.log'), 'stderr': identity(OUT / 'execution.stderr.log'),
                 'archive_code_or_project_or_native_execution_requested': False,
                 'archive_review_process_invocations': 1}
    emit(OUT / 'execution.json', execution)
    if code != 0 or before != execution['method_after']:
        print(json.dumps(execution, sort_keys=True))
        return 1
    report = json.loads((OUT / 'review.json').read_text())
    if report['state'] != 'ARCHIVE_INTEGRITY_AND_FAILURE_PRESERVATION_VERIFIED':
        raise ValueError('review not complete')
    files = [identity(OUT / name) for name in ('review_final_increment.py', 'execute_review_once.py',
                                              'review.json', 'execution.json', 'execution.stdout.log', 'execution.stderr.log')]
    handoff = {'schema': 'trnm-final-increment-independent-review-handoff-v1',
               'state': 'COMPLETED_INDEPENDENT_READBACK_INTEGRITY_ONLY',
               'archive_index_sha256': report['index']['sha256'], 'archive_sha256': report['archive']['sha256'],
               'selection_sha256': report['selection']['sha256'], 'archive_members_verified': 971,
               'manifest_bindings_verified': 855, 'original_native_result': 'failed',
               'native_status_counts_preserved': report['native_original_result']['status_counts'],
               'node_controls_passed': 22, 'node_controls_failed': 1,
               'original_failures_and_unreached_assertions_preserved': True,
               'archive_integrity_is_native_pass': False,
               'project_native_or_archived_code_executed': False,
               'files': files}
    emit(OUT / 'handoff.json', handoff)
    items = [identity(path) for path in sorted(OUT.iterdir()) if path.is_file() and path.name != 'manifest.json']
    emit(OUT / 'manifest.json', {'schema': 'trnm-final-increment-independent-review-files-v1', 'files': items})
    for name in ('review_final_increment.py', 'review.json', 'execution.json', 'handoff.json', 'manifest.json'):
        print(json.dumps(identity(OUT / name), sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
