#!/usr/bin/env python3
"""Capture this task's real commands and raw results outside the source tree."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time

TASK = Path('/workspace/scratch/a4188f5c86b5')
REPO = TASK / 'chain-pq-profile-boundary'


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(
        ['git', '--no-replace-objects', *args], cwd=REPO, text=True
    ).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', required=True)
    parser.add_argument('--id', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.head):
        parser.error('head must be an exact commit')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}', args.id):
        parser.error('invalid record id')
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a real command is required')
    if git('rev-parse', 'HEAD') != args.head:
        raise SystemExit('source HEAD differs before command')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise SystemExit('source is not clean before command')
    report = json.loads((TASK / 'coordination/local-build-environment.json').read_text())
    changes = dict(report['environment'])
    prefix = changes.pop('PATH_prefix')
    environment = dict(os.environ)
    environment.update(changes)
    environment['PATH'] = prefix + os.pathsep + environment.get('PATH', '')
    destination = TASK / 'validation' / args.head / args.id
    destination.mkdir(parents=True, exist_ok=False)
    environment['TRNM_CI_RECEIPT_DIR'] = str(destination / 'native-receipts')
    context = {
        'source_commit': args.head,
        'source_tree': git('rev-parse', 'HEAD^{tree}'),
        'cwd': str(REPO),
        'argv': command,
        'environment': dict(changes, PATH_prefix=prefix,
                            TRNM_CI_RECEIPT_DIR=environment['TRNM_CI_RECEIPT_DIR']),
        'inherited_build_overrides': {
            key: os.environ.get(key) for key in (
                'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTUP_TOOLCHAIN',
                'CARGO_PROFILE_TEST_DEBUG', 'CARGO_PROFILE_DEV_DEBUG')
        },
        'provider_files': report['provider']['five_files'],
        'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'native_result_claimed_before_execution': False,
        'recorder_sha256': sha256(Path(__file__)),
    }
    for item in context['provider_files']:
        if sha256(Path(item['path'])) != item['sha256']:
            raise SystemExit('provider bytes changed before command')
    (destination / 'context.json').write_text(json.dumps(context, indent=2) + '\n')
    print(json.dumps({'event': 'started', 'id': args.id, 'argv': command,
                      'record': str(destination)}), flush=True)
    started = time.monotonic()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with (destination / 'stdout.log').open('wb') as stdout, \
         (destination / 'stderr.log').open('wb') as stderr:
        try:
            completed = subprocess.run(command, cwd=REPO, env=environment,
                                       stdout=stdout, stderr=stderr, check=False)
            code = completed.returncode
            failure = None
        except OSError as error:
            code = None
            failure = str(error)
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    after = git('rev-parse', 'HEAD')
    dirty = git('status', '--porcelain', '--untracked-files=all')
    result = {
        'id': args.id, 'argv': command, 'returncode': code, 'launch_error': failure,
        'elapsed_seconds': time.monotonic() - started,
        'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'source_head_before': args.head, 'source_head_after': after,
        'source_status_after': dirty,
        'stdout_sha256': sha256(destination / 'stdout.log'),
        'stderr_sha256': sha256(destination / 'stderr.log'),
        'pass': code == 0 and after == args.head and not dirty,
        'qualification_granted': False,
        'child_resources': {
            'user_cpu_seconds': usage_after.ru_utime - usage_before.ru_utime,
            'system_cpu_seconds': usage_after.ru_stime - usage_before.ru_stime,
            'maximum_rss_kib': usage_after.ru_maxrss,
            'rss_scope': 'maximum of waited children, including earlier Git metadata children; not an OOM diagnosis',
        },
    }
    (destination / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    for name in ('stdout.log', 'stderr.log'):
        data = (destination / name).read_bytes()
        if data:
            print(name + ' tail:\n' + data[-5000:].decode('utf-8', errors='replace'), flush=True)
    return 0 if result['pass'] else (code if code is not None and 0 < code < 126 else 1)


if __name__ == '__main__':
    sys.exit(main())
